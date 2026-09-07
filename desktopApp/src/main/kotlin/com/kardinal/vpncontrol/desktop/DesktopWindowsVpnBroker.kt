package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.*
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream

/** Actual Windows-only scoped child transport. Public standard-token readiness remains separately gated. */
internal object DesktopWindowsVpnBroker {
    fun start(config: String, logFile: Path): DesktopRuntimeProcess = prepare(config, logFile).use { it.commit() }

    fun prepare(
        config: String,
        logFile: Path,
        onProgress: (DesktopWindowsRuntimePreparationStage) -> Unit = {},
    ): DesktopPreparedRuntimeProcess = prepareCaptured(config, emptyList(), logFile, onProgress)

    fun prepare(
        captured: DesktopWindowsCapturedConfiguration,
        logFile: Path,
        onProgress: (DesktopWindowsRuntimePreparationStage) -> Unit = {},
    ): DesktopPreparedRuntimeProcess = prepareCapturedInput(captured) { config, resources ->
        prepareCaptured(config, resources, logFile, onProgress, captured.mutableResources)
    }

    /** The active launch keeps this lease for exact recovery after ordinary source files change. */
    internal fun prepareRetained(
        captured: DesktopWindowsCapturedConfiguration,
        logFile: Path,
        onProgress: (DesktopWindowsRuntimePreparationStage) -> Unit = {},
    ): DesktopPreparedRuntimeProcess = captured.withSnapshot { config, resources ->
        prepareCaptured(config, resources, logFile, onProgress, captured.mutableResources)
    }

    internal fun prepareRetained(
        captured: DesktopWindowsCapturedConfiguration,
        logFile: Path,
        scope: DesktopWindowsRuntimeResourceScope,
        onProgress: (DesktopWindowsRuntimePreparationStage) -> Unit = {},
    ): DesktopPreparedRuntimeProcess = captured.withSnapshot { config, resources ->
        prepareCaptured(config, resources, logFile, onProgress, captured.mutableResources, scope)
    }

    internal fun prepareCapturedInput(captured: DesktopWindowsCapturedConfiguration,
        prepareNative: (String, List<DesktopWindowsCapturedResource>) -> DesktopPreparedRuntimeProcess,
    ): DesktopPreparedRuntimeProcess {
        var candidate: DesktopPreparedRuntimeProcess? = null
        try {
            return captured.consumeSnapshot { config, resources ->
                prepareNative(config, resources).also { candidate = it }
            }
        } catch (failure: Throwable) {
            // Cleanup follows transfer but precedes return to the runtime transition. If private
            // spools cannot close, do not lose an already accepted suspended child's ownership.
            candidate?.close()
            throw when (failure) {
                is DesktopWindowsRuntimeFailure -> failure
                is OutOfMemoryError -> DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED", stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
                else -> DesktopWindowsRuntimeFailure(if (failure.message == "CONFLICT") "CONFLICT" else "UNAVAILABLE",
                    stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
            }
        }
    }

    /** Ordinary-owner admission surrounds authorization and the helper's preparation acknowledgment. */
    internal fun withNativeOwnerAdmission(native: WindowsAdmissionNative,
                                         prepare: (String) -> DesktopPreparedRuntimeProcess): DesktopPreparedRuntimeProcess {
        fun admissionFailure(failure: Throwable, retained: AutoCloseable? = null): DesktopWindowsRuntimeFailure {
            val original = (failure as? DesktopWindowsAdmissionCleanupFailure)?.originalFailure ?: failure
            val nativeFailure = original as? DesktopWindowsRuntimeFailure
            val leases = listOfNotNull(retained, (failure as? DesktopWindowsAdmissionCleanupFailure)?.retained,
                nativeFailure?.retainedAdmission).distinct().toMutableList()
            val pending = if (leases.isEmpty()) null else object : AutoCloseable {
                @Synchronized override fun close() {
                    var rejected: Throwable? = null
                    for (index in leases.indices.reversed()) {
                        try { leases[index].close(); leases.removeAt(index) }
                        catch (error: Throwable) { rejected = rejected ?: error }
                    }
                    rejected?.let { throw it }
                }
            }
            return DesktopWindowsRuntimeFailure(nativeFailure?.code ?: when (original) {
                is IllegalArgumentException, is SecurityException -> "PERMISSION_DENIED"
                is WindowsInstallNativeFailure -> if (original.code == 5) "PERMISSION_DENIED" else "UNAVAILABLE"
                is OutOfMemoryError -> "RESOURCE_EXHAUSTED"
                is kotlinx.coroutines.CancellationException -> "CANCELLED"
                else -> "UNAVAILABLE"
            }, nativeFailure?.unresolvedRuntime,
                nativeFailure?.stage ?: DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS, pending)
        }
        val sid: String
        val pins: AutoCloseable
        try {
            sid = native.currentSid()
            pins = DesktopWindowsProtectedAncestors.retain(native)
        } catch (failure: Throwable) { throw admissionFailure(failure) }
        var prepared: DesktopPreparedRuntimeProcess? = null
        try {
            val ready = prepare(sid)
            prepared = ready
            try { pins.close() } catch (failure: Throwable) { throw admissionFailure(failure) }
            return ready
        } catch (failure: Throwable) {
            val retained = if (runCatching { pins.close() }.isFailure) pins else null
            // A read-only admission-handle failure after READY must not discard an accepted child.
            try { prepared?.close() }
            catch (cleanup: Throwable) { throw admissionFailure(cleanup, retained) }
            if (retained != null) throw admissionFailure(failure, retained)
            throw failure
        }
    }

    private fun prepareCaptured(config: String, resources: List<DesktopWindowsCapturedResource>, logFile: Path,
                                onProgress: (DesktopWindowsRuntimePreparationStage) -> Unit,
                                mutableResources: List<DesktopWindowsRuntimeResource> = emptyList(),
                                scope: DesktopWindowsRuntimeResourceScope? = null): DesktopPreparedRuntimeProcess {
        if (mutableResources.isNotEmpty()) {
            if (scope == null) throw DesktopWindowsRuntimeFailure("UNAVAILABLE", stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
            // The production gate stays closed until cache leases and protected publication
            // receipts participate in this channel's native exit acknowledgment.
            throw DesktopWindowsRuntimeFailure("UNAVAILABLE", stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
        }
        check(System.getProperty("os.name").startsWith("Windows", true))
        val architecture = System.getProperty("os.arch").lowercase()
        check(architecture in setOf("amd64", "x86_64")) { "UNSUPPORTED" }
        // Never elevate VPN_CONTROL_SING_BOX, PATH, or the user-writable extraction cache.
        val runtime = requireNotNull(javaClass.getResourceAsStream("/bin/windows-amd64/sing-box.exe")) {
            "UNAVAILABLE"
        }.use { it.readNBytes(192 * 1024 * 1024 + 1) }
        require(runtime.size in 1..192 * 1024 * 1024)
        requireAmd64Executable(runtime)
        require(config.isNotEmpty()) { "INVALID_ARGUMENT" }
        val digest = MessageDigest.getInstance("SHA-256").digest(runtime).joinToString("") { "%02x".format(it) }
        return withNativeOwnerAdmission(JnaWindowsInstallAdmission()) { ownerSid ->
        val api = Native.load("kernel32", Api::class.java)
        val creation = Memory(8).use { created -> Memory(24).use { rest ->
            check(api.GetProcessTimes(Kernel32.INSTANCE.GetCurrentProcess(), created, rest, rest.share(8), rest.share(16)))
            created.getLong(0)
        } }
        val name = "vpn-control-vpn-${UUID.randomUUID()}"
        val capturedCommand = command(name, ProcessHandle.current().pid(), creation,
            ownerSid, digest)
        val executable = Memory(65536).use { buffer ->
            val length = api.GetSystemDirectoryW(buffer, 32768)
            check(length in 1 until 32768)
            String(CharArray(length) { buffer.getShort(it.toLong() * 2).toInt().toChar() }) +
                "\\WindowsPowerShell\\v1.0\\powershell.exe"
        }
        val launch = ShellAPI.SHELLEXECUTEINFO().also {
            it.fMask = 0x40
            it.lpVerb = "runas"
            it.lpFile = executable
            it.lpParameters = commandParameters(executable, capturedCommand)
            it.nShow = 0
        }
        val ownedJob = DesktopWindowsNativeJob.create()
        try {
            onProgress(DesktopWindowsRuntimePreparationStage.AUTHORIZATION)
            if (!Shell32.INSTANCE.ShellExecuteEx(launch)) throw launchFailure(Kernel32.INSTANCE.GetLastError())
        } catch (failure: Throwable) { ownedJob.close(); throw failure }
        val broker = launch.hProcess ?: run {
            // No channel input was sent, so no child could be admitted to this empty job.
            ownedJob.close()
            throw DesktopWindowsRuntimeFailure("UNAVAILABLE", stage = DesktopWindowsRuntimePreparationStage.AUTHORIZATION)
        }
        val channel = NativeChannel(api, name, broker, ownedJob)
        val retained = DesktopWindowsScopedRuntimeProcess(channel, logFile)
        var stage = DesktopWindowsRuntimePreparationStage.HELPER_CONNECTION
        try {
            onProgress(stage)
            val pipe = channel.connect()
            stage = DesktopWindowsRuntimePreparationStage.PEER_IDENTITY
            onProgress(stage)
            val brokerPid = Kernel32.INSTANCE.GetProcessId(broker)
            val server = IntByReference()
            check(api.GetNamedPipeServerProcessId(pipe, server) && server.value == brokerPid) { "PERMISSION_DENIED" }
            stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS
            onProgress(stage)
            channel.initialize(runtime, config, resources) {
                stage = DesktopWindowsRuntimePreparationStage.CHILD_CREATED
                onProgress(stage)
            }
            stage = DesktopWindowsRuntimePreparationStage.READY
            onProgress(stage)
            DesktopPreparedWindowsRuntimeProcess(channel, logFile)
        } catch (failure: Throwable) {
            throw desktopWindowsPreparationFailure(failure, stage,
                abort = channel::abort, close = channel::close, unresolved = { retained },
            )
        }
        }
    }

    internal fun launchFailure(error: Int): DesktopWindowsRuntimeFailure = DesktopWindowsRuntimeFailure(
        when (error) { 1223 -> "CANCELLED"; 5 -> "PERMISSION_DENIED"; else -> "UNAVAILABLE" },
        stage = DesktopWindowsRuntimePreparationStage.AUTHORIZATION,
    )

    internal fun requireAmd64Executable(image: ByteArray) {
        require(image.size >= 64 && image[0] == 0x4d.toByte() && image[1] == 0x5a.toByte()) { "UNSUPPORTED" }
        val buffer = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)
        val offset = buffer.getInt(0x3c)
        require(offset >= 64 && offset <= image.size - 6 && buffer.getInt(offset) == 0x4550 &&
            buffer.getShort(offset + 4).toInt() and 0xffff == 0x8664) { "UNSUPPORTED" }
    }

    internal fun retainedOverlapped(event: WinNT.HANDLE): WinBase.OVERLAPPED =
        WinBase.OVERLAPPED().also {
            it.hEvent = event
            // The kernel owns Internal/InternalHigh until completion. JNA's automatic write before
            // GetOverlappedResultEx can overwrite a racing completion with the old pending state.
            it.setAutoSynch(false)
            it.write()
        }

    /** Bounded native frames, without a second full UTF8 array or a document-size product ceiling. */
    internal fun writeConfiguration(config: String, writeFrame: (ByteArray, Int, Int) -> Unit) {
        val digest = MessageDigest.getInstance("SHA-256")
        var count = 0L
        fun integer(value: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
        val stream = object : OutputStream() {
            override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                var position = offset
                while (position < offset + length) {
                    val size = minOf(65536, offset + length - position)
                    val header = integer(size)
                    writeFrame(header, 0, header.size)
                    writeFrame(bytes, position, size)
                    digest.update(bytes, position, size)
                    count = Math.addExact(count, size.toLong())
                    position += size
                }
            }
        }
        OutputStreamWriter(stream, Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)).use { writer -> config.reader().use { it.transferTo(writer) } }
        val trailer = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putInt(0).putLong(count).array()
        writeFrame(trailer, 0, trailer.size)
        val hash = digest.digest()
        writeFrame(hash, 0, hash.size)
    }

    internal fun command(name: String, pid: Long, creation: Long, sid: String, digest: String): String {
        require(name.matches(Regex("vpn-control-vpn-[a-f0-9-]{36}")))
        require(pid in 1..0xffffffffL && creation > 0 && sid.matches(Regex("S-1-[0-9-]+")) && digest.matches(Regex("[a-f0-9]{64}")))
        try {
            val compressed = ByteArrayOutputStream().also { output -> GZIPOutputStream(output).use { gzip ->
                for (resource in listOf("/windows-vpn-broker.cs", "/windows-vpn-user-files.cs", "/windows-vpn-cache-resources.cs")) {
                    requireNotNull(javaClass.getResourceAsStream(resource)).use { it.copyTo(gzip, 65536) }
                    gzip.write('\n'.code)
                }
            } }.toByteArray()
            return """
            ${'$'}ErrorActionPreference='Stop'
            ${'$'}m=New-Object IO.MemoryStream(,[Convert]::FromBase64String('${Base64.getEncoder().encodeToString(compressed)}'))
            ${'$'}g=New-Object IO.Compression.GZipStream(${'$'}m,[IO.Compression.CompressionMode]::Decompress)
            ${'$'}r=New-Object IO.StreamReader(${'$'}g)
            Add-Type -TypeDefinition ${'$'}r.ReadToEnd() -ReferencedAssemblies @('System.dll','System.Core.dll','System.Web.Extensions.dll')
            [VpnRuntimeBroker]::Run('$name',$pid,[long]$creation,'$sid','$digest')
            """.trimIndent()
        } catch (_: OutOfMemoryError) {
            throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED", stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
        }
    }

    internal fun commandParameters(executable: String, capturedCommand: String): String {
        // This operand contains only fixed ASCII code/base64 and validated opaque peer identities.
        // Runtime configuration, user paths and credentials travel solely over the authenticated pipe.
        require(executable.isNotEmpty() && '\u0000' !in executable && capturedCommand.all { it.code in 1..127 })
        val parameters = listOf("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
            "-Command", capturedCommand).joinToString(" ", transform = ::windowsInstallArgument)
        // Count the actual UTF-16 CreateProcess command, including executable quoting and its NUL.
        // The native argv limit bounds captured helper code; it never limits the logical document.
        if (windowsInstallArgument(executable).length.toLong() + parameters.length + 2 > 32767) {
            throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED", stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
        }
        return parameters
    }

    private fun connect(api: Api, name: String, broker: WinNT.HANDLE): WinNT.HANDLE {
        val path = WString("\\\\.\\pipe\\$name")
        val started = System.nanoTime()
        while (System.nanoTime() - started < TimeUnit.SECONDS.toNanos(180)) {
            check(Kernel32.INSTANCE.WaitForSingleObject(broker, 0) == 258) { "UNAVAILABLE" }
            // Identification-only SQOS prevents impersonation by a raced pipe before server PID validation.
            val pipe = api.CreateFileW(path, 0xc0000000.toInt(), 0, null, 3, 0x40110000, null)
            if (pipe != WinBase.INVALID_HANDLE_VALUE) return pipe
            Thread.sleep(25)
        }
        throw IOException("TIMEOUT")
    }

    private class NativeChannel(private val api: Api, private val pipeName: String,
        private val broker: WinNT.HANDLE, private val ownedJob: DesktopWindowsNativeJob) : DesktopWindowsPreparedRuntimeChannel {
        override var childPid: Long = 0; private set
        private var pipe: WinNT.HANDLE? = null
        private var pending = DesktopWindowsRuntimeStatus(true)
        private var closed = false
        private var pipeClosed = false
        private var committed = false
        fun connect(): WinNT.HANDLE = connect(api, pipeName, broker).also { pipe = it }
        fun initialize(runtime: ByteArray, configuration: String, resources: List<DesktopWindowsCapturedResource>,
                       childCreated: () -> Unit) {
            write(integer(4))
            write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(ownedJob.handleValue).array())
            write(integer(runtime.size)); write(runtime)
            writeConfiguration(configuration, ::write)
            write(integer(resources.size))
            for (resource in resources) {
                for (metadata in listOf(resource.id, resource.extension)) {
                    val bytes = metadata.toByteArray(Charsets.US_ASCII)
                    write(integer(bytes.size)); write(bytes)
                }
                var offset = 0L
                while (offset < resource.byteCount) {
                    val bytes = resource.read(offset, minOf(65536L, resource.byteCount - offset).toInt())
                    write(integer(bytes.size)); write(bytes); offset += bytes.size
                }
                write(ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putInt(0).putLong(offset).array())
                write(resource.sha256.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
            }
            when (read(1).single().toInt()) {
                0 -> Unit
                1 -> throw DesktopWindowsRuntimeFailure("INVALID_ARGUMENT")
                2 -> throw DesktopWindowsRuntimeFailure("PERMISSION_DENIED")
                3 -> throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED")
                else -> throw DesktopWindowsRuntimeFailure("UNAVAILABLE")
            }
            childCreated()
            childPid = ByteBuffer.wrap(read(4)).order(ByteOrder.LITTLE_ENDIAN).int.toLong()
            check(childPid > 0) { "INCOMPATIBLE_PROTOCOL" }
        }
        @Synchronized override fun commit() {
            check(!closed && !committed && childPid > 0)
            // The candidate was created suspended. This is the only command that may execute it.
            write(byteArrayOf(3))
            if (read(1).single() != 0.toByte()) throw DesktopWindowsRuntimeFailure("RUNTIME_START_FAILED")
            committed = true
        }
        @Synchronized override fun abort(): Boolean {
            // Cancellation can arrive before the helper finishes compiling its fixed source.
            // Open and immediately close its pipe when ready; no input is sent before peer admission.
            if (pipe == null && !closed) {
                val candidate = api.CreateFileW(WString("\\\\.\\pipe\\$pipeName"),
                    0xc0000000.toInt(), 0, null, 3, 0x40110000, null)
                if (candidate != WinBase.INVALID_HANDLE_VALUE) pipe = candidate
            }
            closePipe()
            ownedJob.terminate()
            // Waiting for the exact helper also prevents a later suspended child appearing after
            // an initially empty job was observed. Never depend on elevation-token process rights.
            return Kernel32.INSTANCE.WaitForSingleObject(broker, 10000) == 0 && ownedJob.isEmpty()
        }
        @Synchronized override fun status(): DesktopWindowsRuntimeStatus {
            if (!pending.running) return pending.also { pending = it.copy(log = byteArrayOf()) }
            return exchange(0)
        }
        @Synchronized override fun stop(force: Boolean) { pending = exchange(if (force) 2 else 1) }
        override fun childExited() = closed ||
            (Kernel32.INSTANCE.WaitForSingleObject(broker, 0) == 0 && ownedJob.isEmpty())
        private fun exchange(command: Int): DesktopWindowsRuntimeStatus {
            check(!closed)
            write(byteArrayOf(command.toByte()))
            val alive = read(1).single().toInt()
            check(alive in 0..1)
            val size = ByteBuffer.wrap(read(4)).order(ByteOrder.LITTLE_ENDIAN).int
            check(size in 0..65536)
            return DesktopWindowsRuntimeStatus(alive == 1, read(size)).also { pending = it.copy(log = byteArrayOf()) }
        }
        private fun integer(value: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
        private fun write(bytes: ByteArray, start: Int = 0, length: Int = bytes.size) {
            var offset = start
            while (offset < start + length) {
                val count = minOf(65536, start + length - offset)
                Memory(count.toLong()).use { buffer ->
                    buffer.write(0, bytes, offset, count)
                    offset += io(buffer, count, true)
                }
            }
        }
        private fun read(size: Int): ByteArray {
            val result = ByteArray(size)
            var offset = 0
            while (offset < size) Memory((size - offset).toLong()).use { buffer ->
                val count = io(buffer, size - offset, false)
                buffer.read(0, result, offset, count); offset += count
            }
            return result
        }
        private fun io(buffer: Memory, count: Int, write: Boolean): Int {
            val activePipe = checkNotNull(pipe) { "OUTCOME_UNKNOWN" }
            check(!pipeClosed) { "OUTCOME_UNKNOWN" }
            val event = Kernel32.INSTANCE.CreateEvent(null, true, false, null)
            check(event != null)
            val overlapped = retainedOverlapped(event)
            val transferred = IntByReference()
            try {
                val done = if (write) api.WriteFile(activePipe, buffer, count, transferred, overlapped)
                    else api.ReadFile(activePipe, buffer, count, transferred, overlapped)
                if (!done) {
                    if (Kernel32.INSTANCE.GetLastError() != 997) throw IOException("OUTCOME_UNKNOWN")
                    if (!api.GetOverlappedResultEx(activePipe, overlapped, transferred, 15000, false)) {
                        api.CancelIoEx(activePipe, overlapped)
                        // Cancellation is not completion: retain OVERLAPPED/buffer until the exact IO is drained.
                        api.GetOverlappedResult(activePipe, overlapped, transferred, true)
                        throw IOException("OUTCOME_UNKNOWN")
                    }
                }
                check(transferred.value in 1..count) { "OUTCOME_UNKNOWN" }
                return transferred.value
            } finally { Kernel32.INSTANCE.CloseHandle(event) }
        }
        private fun closePipe() {
            if (!pipeClosed && pipe != null) {
                check(Kernel32.INSTANCE.CloseHandle(pipe)) { "OUTCOME_UNKNOWN" }
                pipeClosed = true
            }
        }
        @Synchronized override fun close() {
            if (closed) return
            check(Kernel32.INSTANCE.WaitForSingleObject(broker, 10000) == 0 && ownedJob.isEmpty()) { "OUTCOME_UNKNOWN" }
            closePipe()
            ownedJob.close()
            check(Kernel32.INSTANCE.CloseHandle(broker)) { "OUTCOME_UNKNOWN" }
            closed = true
        }
    }
    private interface Api : StdCallLibrary {
        fun GetSystemDirectoryW(output: Pointer, capacity: Int): Int
        fun GetProcessTimes(process: WinNT.HANDLE, creation: Pointer, exit: Pointer, kernel: Pointer, user: Pointer): Boolean
        fun CreateFileW(path: WString, access: Int, share: Int, security: Pointer?, disposition: Int, flags: Int,
            template: WinNT.HANDLE?): WinNT.HANDLE
        fun GetNamedPipeServerProcessId(pipe: WinNT.HANDLE, pid: IntByReference): Boolean
        fun ReadFile(pipe: WinNT.HANDLE, buffer: Pointer, count: Int, transferred: IntByReference, overlapped: WinBase.OVERLAPPED): Boolean
        fun WriteFile(pipe: WinNT.HANDLE, buffer: Pointer, count: Int, transferred: IntByReference, overlapped: WinBase.OVERLAPPED): Boolean
        fun GetOverlappedResultEx(pipe: WinNT.HANDLE, overlapped: WinBase.OVERLAPPED, transferred: IntByReference, timeout: Int, alertable: Boolean): Boolean
        fun GetOverlappedResult(pipe: WinNT.HANDLE, overlapped: WinBase.OVERLAPPED, transferred: IntByReference, wait: Boolean): Boolean
        fun CancelIoEx(pipe: WinNT.HANDLE, overlapped: WinBase.OVERLAPPED): Boolean
    }
}
