package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.HomeSshRouteConfigBuilder
import com.kardinal.vpncontrol.data.HomeSshRouteRuntimeOptions
import com.sun.jna.Platform
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.FileSystemException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.delay

/**
 * The SSH Routing bootstrap: a sing-box of its own that carries one subscription download while no runtime is
 * active (CONFIG-004's direct exception; an active runtime's management inbound carries it otherwise, CONFIG-005).
 *
 * Its configuration names the imported key by path ([HomeSshRouteConfigBuilder] writes `private_key_path`), so no
 * key material is written here. The file is created owner-only on POSIX ([Files.createTempFile]) and deleted as soon
 * as sing-box listens, having read it; sing-box's own output is discarded, so there is no log file. Before [useProxy]
 * returns, the child has ended and the file is gone, or the owner's stderr says what is left
 * ([DesktopBootstrapCleanup]): the download's result is the owner's word that the bootstrap left nothing behind.
 *
 * The child holds an authenticated SSH session behind a loopback inbound without users, so it must not outlive its
 * owner either ([DesktopShortLivedRuntime]): a JVM shutdown ends it, Windows ends it with the owner's last handle to
 * its job, and the next owner start ends one a killed owner left on POSIX ([reapStale]).
 */
internal class DesktopHomeSshBootstrapProxy(
    private val baseDir: Path,
    private val singBoxResolver: DesktopSingBoxResolver,
    private val launch: (List<String>, Path) -> Process = ::launchBootstrapRuntime,
    private val cleanup: DesktopBootstrapCleanup = DesktopBootstrapCleanup(),
    private val tie: (Process) -> AutoCloseable? = ::tieToOwnerLifetime,
    private val children: DesktopShortLivedRuntimes = DesktopShortLivedRuntimes.shared,
) {
    suspend fun <T> useProxy(
        options: HomeSshRouteRuntimeOptions,
        block: (Int) -> T,
    ): T {
        Files.createDirectories(baseDir)
        val port = DesktopLoopback.freePort()
        // Resolved before any file exists, so a missing sing-box leaves nothing behind.
        val binary = singBoxResolver.resolve() ?: error(singBoxResolver.missingMessage())
        return DesktopShortLivedRuntime(cleanup, tie).within(children) { runtime ->
            val config = runtime.createFile(baseDir, FILE_PREFIX, ".json")
            Files.writeString(config, HomeSshRouteConfigBuilder.buildBootstrapProxyConfig(options, port).toString())
            val process = runtime.start { launch(listOf(binary.path.toString(), "run", "-c", config.toString()), baseDir) }
            require(waitForPort(process, port)) { "SSH relay did not become ready" }
            // sing-box read its configuration before it listened. A refused deletion is retried and reported below.
            cleanup.deleteNow(config)
            block(port)
        }
    }

    private suspend fun waitForPort(process: Process, port: Int): Boolean {
        repeat(30) {
            if (!process.isAlive) return false
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300) }
                return true
            } catch (_: IOException) {
                delay(100)
            }
        }
        return false
    }

    internal companion object {
        const val FILE_PREFIX = "home-ssh-bootstrap-"

        /** What a killed owner left in the runtime folder; run at owner start, under the single-instance lock. */
        fun reapStale(baseDir: Path, cleanup: DesktopBootstrapCleanup = DesktopBootstrapCleanup()) =
            reapStaleShortLivedRuntimes(baseDir, listOf(FILE_PREFIX), cleanup)
    }
}

/**
 * Starts the bootstrap's sing-box in [directory] with its output discarded: nothing reads it, and a log file is one
 * more file that Windows refuses to delete while the child's handles live, since the JVM opens a redirect file
 * without delete sharing and the child inherits that handle.
 */
internal fun launchBootstrapRuntime(command: List<String>, directory: Path): Process =
    ProcessBuilder(command)
        .directory(directory.toFile())
        .redirectErrorStream(true)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .start()

/**
 * Windows: puts [process] in a job of its own that ends it when the owner's last handle to the job closes, which the
 * kernel does when the owner ends in any way (End task, `taskkill /F`, a crash). Elsewhere null: a JVM shutdown
 * ([DesktopShortLivedRuntimes]) and the next owner start ([reapStaleShortLivedRuntimes]) cover the owner's end there.
 */
internal fun tieToOwnerLifetime(process: Process): AutoCloseable? {
    if (!Platform.isWindows()) return null
    val job = DesktopWindowsNativeJob.create()
    if (!job.assign(process.pid())) {
        job.release()
        throw IOException("the job refused the child")
    }
    return AutoCloseable { job.release() }
}

/**
 * One short-lived sing-box of this owner (the SSH Routing bootstrap, a Find Best candidate, the direct probe) and the
 * files it was given. [within] registers it with [DesktopShortLivedRuntimes] before its first file exists, so a JVM
 * shutdown from then on ends the child and removes the files, and [finish] runs once, whoever comes first: the
 * owner's own `finally` or the shutdown, which waits for a [finish] already under way.
 */
internal class DesktopShortLivedRuntime(
    private val cleanup: DesktopBootstrapCleanup,
    private val tie: (Process) -> AutoCloseable? = ::tieToOwnerLifetime,
) {
    private val files = mutableListOf<Path>()
    private var process: Process? = null
    private var tied: AutoCloseable? = null
    private var finished = false

    inline fun <T> within(children: DesktopShortLivedRuntimes, block: (DesktopShortLivedRuntime) -> T): T {
        val registration = children.register(this)
        try {
            return block(this)
        } finally {
            try {
                finish()
            } finally {
                registration.close()
            }
        }
    }

    @Synchronized fun createFile(directory: Path, prefix: String, suffix: String): Path {
        check(!finished) { "VPN Control is shutting down" }
        return Files.createTempFile(directory, prefix, suffix).also(files::add)
    }

    @Synchronized fun start(launch: () -> Process): Process {
        check(!finished) { "VPN Control is shutting down" }
        val started = launch()
        process = started
        tied = try {
            tie(started)
        } catch (failure: Exception) {
            cleanup.note("sing-box is not tied to the owner's lifetime (${failure.javaClass.simpleName})")
            null
        }
        return started
    }

    @Synchronized fun finish() {
        if (finished) return
        finished = true
        try {
            cleanup.finish(process, files.toList())
        } finally {
            tied?.let { runCatching { it.close() } }
        }
    }
}

/** This JVM's live short-lived runtimes, finished by one shutdown hook installed with the first of them. */
internal class DesktopShortLivedRuntimes(
    private val registerHook: (Thread) -> Unit = { Runtime.getRuntime().addShutdownHook(it) },
) {
    private val live = LinkedHashSet<DesktopShortLivedRuntime>()
    private var hookInstalled = false
    private var shuttingDown = false

    /** Throws once the JVM shuts down, before the runtime has a file or a child. */
    @Synchronized fun register(runtime: DesktopShortLivedRuntime): AutoCloseable {
        check(!shuttingDown) { "VPN Control is shutting down" }
        if (!hookInstalled) {
            registerHook(Thread(::finishAll, "short-lived-runtime-shutdown"))
            hookInstalled = true
        }
        live += runtime
        return AutoCloseable { synchronized(this) { live -= runtime } }
    }

    fun finishAll() {
        val all = synchronized(this) {
            shuttingDown = true
            live.toList()
        }
        for (runtime in all) {
            try {
                runtime.finish()
            } catch (_: Exception) {
            }
        }
    }

    internal companion object {
        val shared = DesktopShortLivedRuntimes()
    }
}

/**
 * What an owner that ended without its `finally` left in [baseDir]: each sing-box still running one of the folder's
 * short-lived configurations (`run -c <baseDir>/<prefix>*.json`, found by its arguments, which Linux and macOS
 * report for the same user's processes; Windows ends such a child with its job instead), then each file named with one
 * of [prefixes], removed as [DesktopBootstrapCleanup] removes them. Run at owner start, under the single-instance
 * lock, before this owner starts one of its own. Each ended process is reported by pid and each removed file by leaf.
 */
internal fun reapStaleShortLivedRuntimes(
    baseDir: Path,
    prefixes: List<String>,
    cleanup: DesktopBootstrapCleanup,
    processes: () -> List<ProcessHandle> = { ProcessHandle.allProcesses().use { it.toList() } },
) {
    if (!Files.isDirectory(baseDir)) return
    val folders = setOfNotNull(baseDir.toAbsolutePath().normalize(), runCatching { baseDir.toRealPath() }.getOrNull())
    val me = ProcessHandle.current()
    val user = me.info().user().orElse(null)
    for (handle in processes()) {
        if (handle.pid() == me.pid()) continue
        val info = runCatching { handle.info() }.getOrNull() ?: continue
        val arguments = info.arguments().orElse(null) ?: continue
        if (user != null && info.user().map { it != user }.orElse(false)) continue
        if (!runsShortLivedConfiguration(arguments.toList(), folders, prefixes)) continue
        cleanup.endStale(handle)
    }
    val names = Files.list(baseDir).use { paths ->
        paths.filter { path ->
            val name = path.fileName.toString()
            prefixes.any(name::startsWith) && !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
        }.sorted().toList()
    }
    for (file in names) cleanup.removeStale(file)
}

private fun runsShortLivedConfiguration(arguments: List<String>, folders: Set<Path>, prefixes: List<String>): Boolean {
    for (index in 0 until arguments.size - 2) {
        if (arguments[index] != "run" || arguments[index + 1] != "-c") continue
        val config = runCatching { Path.of(arguments[index + 2]).toAbsolutePath().normalize() }.getOrNull() ?: continue
        val name = config.fileName?.toString() ?: continue
        if (!name.endsWith(".json") || prefixes.none(name::startsWith)) continue
        val parent = config.parent ?: continue
        if (parent in folders || runCatching { parent.toRealPath() }.getOrNull() in folders) return true
    }
    return false
}

/**
 * Ends a bootstrap's sing-box, then deletes its files once the operating system lets go of them.
 *
 * Windows keeps a file in use for a while after a child is told to end. [Process.waitFor] with a timeout,
 * [Process.isAlive] and [Process.onExit] answer from the exit code, which the kernel can set before it has closed
 * the process's handles; only the untimed [Process.waitFor] waits for the process object itself, signalled after
 * them, so it runs on a daemon thread, awaited for [exitMillis]. A scanner may also hold a file just written or
 * closed, so a deletion the file system refuses is retried with a bounded backoff, and so is a deletion whose name is
 * still listed afterwards (a delete-pending name where the volume lacks POSIX delete semantics). What still fails is
 * never swallowed: one line each on the owner's stderr (the serve's own stderr, `headless.log` of an owner a CLI
 * started) names the file's leaf and the refusal, never a folder or the file's contents. [label] names the runtime.
 */
internal class DesktopBootstrapCleanup(
    private val delete: (Path) -> Unit = { Files.deleteIfExists(it) },
    private val gone: (Path) -> Boolean = { Files.notExists(it, LinkOption.NOFOLLOW_LINKS) },
    private val sleep: (Long) -> Unit = { Thread.sleep(it) },
    private val report: (String) -> Unit = { writeDesktopCliLine(System.err, it) },
    private val graceMillis: Long = 2_000,
    private val exitMillis: Long = 5_000,
    private val retryDelaysMillis: List<Long> = RETRY_DELAYS_MILLIS,
    private val label: String = "SSH Routing bootstrap",
) {
    /** One attempt while the file may still be in use; [finish] retries it and reports what stays. */
    fun deleteNow(path: Path) {
        try {
            delete(path)
        } catch (_: IOException) {
        }
    }

    fun finish(process: Process?, files: List<Path>) {
        if (process != null && !stop(process)) {
            note("sing-box was not seen to end within $exitMillis ms of being stopped")
        }
        for (file in files) {
            val (refusal, attempts) = removeCounting(file)
            if (refusal == null) continue
            note("${file.fileName} was not removed after $attempts ${if (attempts == 1) "attempt" else "attempts"} " +
                "(${describe(refusal)})")
        }
    }

    /** Asks the child to end, kills it after [graceMillis], and says whether its process object ended in time. */
    fun stop(process: Process): Boolean {
        process.destroy()
        val ended = try {
            process.waitFor(graceMillis, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!ended) process.destroyForcibly()
        return awaitProcessObject(process)
    }

    /** Whether [process]'s process object (not only its exit code) ended within [exitMillis]; never asks it to end. */
    fun awaitEnded(process: Process): Boolean = awaitProcessObject(process)

    /** A sing-box an earlier owner left running: asked to end, killed after [graceMillis], reported by pid. */
    fun endStale(handle: ProcessHandle) {
        val ended = try {
            handle.destroy()
            awaitHandle(handle, graceMillis) || run {
                handle.destroyForcibly()
                awaitHandle(handle, exitMillis)
            }
        } catch (_: Exception) {
            false
        }
        note(if (ended) "ended a sing-box an earlier owner left running (pid ${handle.pid()})"
            else "a sing-box an earlier owner left running was not seen to end (pid ${handle.pid()})")
    }

    /** A file an earlier owner left: removed with the bounded retries, reported by leaf either way. */
    fun removeStale(path: Path) {
        val (refusal, attempts) = removeCounting(path)
        note(if (refusal == null) "removed ${path.fileName}, which an earlier owner left"
            else "${path.fileName}, which an earlier owner left, was not removed after $attempts " +
                "${if (attempts == 1) "attempt" else "attempts"} (${describe(refusal)})")
    }

    /** Null once [path] is gone; otherwise the last refusal, after the bounded retries. */
    fun remove(path: Path): IOException? = removeCounting(path).first

    /** One line on the owner's stderr, prefixed with [label]; a failing sink never escapes. */
    fun note(line: String) {
        try {
            report("$label: $line")
        } catch (_: Exception) {
        }
    }

    /**
     * Removes [paths] in their order, a folder after what it held: each pass tries every path still present, and the
     * passes follow the bounded backoff, so the whole set takes one bound however many paths the OS keeps refusing.
     * Each path that stays is reported by leaf like [finish] does; they are returned in their order.
     */
    fun removeAll(paths: List<Path>): List<Path> {
        val refusals = LinkedHashMap<Path, Pair<IOException, Int>>()
        var pending = paths
        for (attempt in 0..retryDelaysMillis.size) {
            if (attempt > 0) {
                try {
                    sleep(retryDelaysMillis[attempt - 1])
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                }
            }
            pending = pending.filter { path ->
                val refusal = deleteOnce(path)
                if (refusal == null) refusals.remove(path) else refusals[path] = refusal.first to attempt + 1
                refusal?.second == true
            }
            if (pending.isEmpty()) break
        }
        for ((path, refusal) in refusals) {
            val (failure, attempts) = refusal
            note("${path.fileName} was not removed after $attempts ${if (attempts == 1) "attempt" else "attempts"} " +
                "(${describe(failure)})")
        }
        return paths.filter(refusals::containsKey)
    }

    /** The last refusal, or null once [path] is gone, with the number of deletions tried. */
    private fun removeCounting(path: Path): Pair<IOException?, Int> {
        var refusal: IOException? = null
        for (attempt in 0..retryDelaysMillis.size) {
            if (attempt > 0) {
                try {
                    sleep(retryDelaysMillis[attempt - 1])
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return refusal to attempt
                }
            }
            val outcome = deleteOnce(path) ?: return null to attempt + 1
            refusal = outcome.first
            if (!outcome.second) return refusal to attempt + 1
        }
        return refusal to retryDelaysMillis.size + 1
    }

    /** Null once [path] is gone; otherwise the refusal and whether another attempt may succeed. */
    private fun deleteOnce(path: Path): Pair<IOException, Boolean>? = try {
        delete(path)
        if (gone(path)) null else FileSystemException(path.fileName.toString(), null, "still listed after its deletion") to true
    } catch (failure: FileSystemException) {
        // A sharing violation or access denied (a delete-pending name) on Windows; EACCES, EPERM or EBUSY elsewhere;
        // a folder that still holds a file (DirectoryNotEmptyException) until that file is gone.
        failure to true
    } catch (failure: IOException) {
        failure to false
    }

    private fun awaitHandle(handle: ProcessHandle, millis: Long): Boolean = try {
        handle.onExit().get(millis, TimeUnit.MILLISECONDS)
        true
    } catch (_: java.util.concurrent.TimeoutException) {
        !handle.isAlive
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        !handle.isAlive
    } catch (_: java.util.concurrent.ExecutionException) {
        !handle.isAlive
    }

    private fun awaitProcessObject(process: Process): Boolean {
        val ended = CountDownLatch(1)
        val waiter = Thread({
            try {
                process.waitFor()
            } catch (_: InterruptedException) {
            } finally {
                ended.countDown()
            }
        }, "short-lived-runtime-exit")
        waiter.isDaemon = true
        waiter.start()
        return try {
            ended.await(exitMillis, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    private fun describe(failure: IOException): String {
        val reason = (failure as? FileSystemException)?.reason?.takeIf(String::isNotBlank)
        return if (reason == null) failure.javaClass.simpleName else "${failure.javaClass.simpleName}: $reason"
    }

    internal companion object {
        /** Eight attempts over about 3.2 s. */
        val RETRY_DELAYS_MILLIS = listOf(25L, 50L, 100L, 200L, 400L, 800L, 1_600L)
    }
}

/** Labels of the owner's short-lived runtimes on its stderr. */
internal const val VALIDATION_RUNTIME_LABEL = "Find Best validation"
internal const val CONNECTION_RUNTIME_LABEL = "Connection runtime"
internal const val DIRECT_PROBE_LABEL = "Direct probe"
internal const val VALIDATION_FILE_PREFIX = "validate-"
internal const val DIRECT_PROBE_FILE_PREFIX = "direct-probe-"

/**
 * At owner start: the SSH Routing bootstrap's files and children in the runtime folder, then the Find Best candidates'
 * and the direct probe's in the validation folder. A failure here never stops the owner; each step reports itself.
 */
internal fun reapShortLivedRuntimesAtOwnerStart(runtimeDirectory: Path, validationDirectory: Path) {
    try {
        DesktopHomeSshBootstrapProxy.reapStale(runtimeDirectory)
    } catch (_: Exception) {
    }
    try {
        reapStaleShortLivedRuntimes(validationDirectory, listOf(VALIDATION_FILE_PREFIX, DIRECT_PROBE_FILE_PREFIX),
            DesktopBootstrapCleanup(label = VALIDATION_RUNTIME_LABEL))
    } catch (_: Exception) {
    }
}
