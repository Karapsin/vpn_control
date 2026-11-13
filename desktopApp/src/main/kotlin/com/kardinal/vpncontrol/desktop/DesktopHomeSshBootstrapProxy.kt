package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.HomeSshRouteConfigBuilder
import com.kardinal.vpncontrol.data.HomeSshRouteRuntimeOptions
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
 */
internal class DesktopHomeSshBootstrapProxy(
    private val baseDir: Path,
    private val singBoxResolver: DesktopSingBoxResolver,
    private val launch: (List<String>, Path) -> Process = ::launchBootstrapRuntime,
    private val cleanup: DesktopBootstrapCleanup = DesktopBootstrapCleanup(),
) {
    suspend fun <T> useProxy(
        options: HomeSshRouteRuntimeOptions,
        block: (Int) -> T,
    ): T {
        Files.createDirectories(baseDir)
        val port = DesktopLoopback.freePort()
        // Resolved before any file exists, so a missing sing-box leaves nothing behind.
        val binary = singBoxResolver.resolve() ?: error(singBoxResolver.missingMessage())
        val config = Files.createTempFile(baseDir, FILE_PREFIX, ".json")
        var process: Process? = null
        try {
            Files.writeString(config, HomeSshRouteConfigBuilder.buildBootstrapProxyConfig(options, port).toString())
            process = launch(listOf(binary.path.toString(), "run", "-c", config.toString()), baseDir)
            require(waitForPort(process, port)) { "SSH relay did not become ready" }
            // sing-box read its configuration before it listened. A refused deletion is retried and reported below.
            cleanup.deleteNow(config)
            return block(port)
        } finally {
            cleanup.finish(process, listOf(config))
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
 * Ends a bootstrap's sing-box, then deletes its files once the operating system lets go of them.
 *
 * Windows keeps a file in use for a while after a child is told to end. [Process.waitFor] with a timeout,
 * [Process.isAlive] and [Process.onExit] answer from the exit code, which the kernel can set before it has closed
 * the process's handles; only the untimed [Process.waitFor] waits for the process object itself, signalled after
 * them, so it runs on a daemon thread, awaited for [exitMillis]. A scanner may also hold a file just written or
 * closed, so a deletion the file system refuses is retried with a bounded backoff, and so is a deletion whose name is
 * still listed afterwards (a delete-pending name where the volume lacks POSIX delete semantics). What still fails is
 * never swallowed: one line each on the owner's stderr (the serve's own stderr, `headless.log` of an owner a CLI
 * started) names the file's leaf and the refusal, never a folder or the file's contents.
 */
internal class DesktopBootstrapCleanup(
    private val delete: (Path) -> Unit = { Files.deleteIfExists(it) },
    private val gone: (Path) -> Boolean = { Files.notExists(it, LinkOption.NOFOLLOW_LINKS) },
    private val sleep: (Long) -> Unit = { Thread.sleep(it) },
    private val report: (String) -> Unit = { writeDesktopCliLine(System.err, it) },
    private val graceMillis: Long = 2_000,
    private val exitMillis: Long = 5_000,
    private val retryDelaysMillis: List<Long> = RETRY_DELAYS_MILLIS,
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
            say("SSH Routing bootstrap: sing-box was not seen to end within $exitMillis ms of being stopped")
        }
        for (file in files) {
            val (refusal, attempts) = removeCounting(file)
            if (refusal == null) continue
            say("SSH Routing bootstrap: ${file.fileName} was not removed after $attempts " +
                "${if (attempts == 1) "attempt" else "attempts"} (${describe(refusal)})")
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

    /** Null once [path] is gone; otherwise the last refusal, after the bounded retries. */
    fun remove(path: Path): IOException? = removeCounting(path).first

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
            try {
                delete(path)
                if (gone(path)) return null to attempt + 1
                refusal = FileSystemException(path.fileName.toString(), null, "still listed after its deletion")
            } catch (failure: FileSystemException) {
                // A sharing violation or access denied (a delete-pending name) on Windows; EACCES, EPERM or EBUSY elsewhere.
                refusal = failure
            } catch (failure: IOException) {
                return failure to attempt + 1
            }
        }
        return refusal to retryDelaysMillis.size + 1
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
        }, "ssh-bootstrap-exit")
        waiter.isDaemon = true
        waiter.start()
        return try {
            ended.await(exitMillis, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    private fun say(line: String) {
        try {
            report(line)
        } catch (_: Exception) {
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
