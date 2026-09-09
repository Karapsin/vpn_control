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
import java.util.UUID
import java.util.concurrent.TimeUnit

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
        scopeProvider: DesktopWindowsRuntimeResourceScopeProvider,
        onProgress: (DesktopWindowsRuntimePreparationStage) -> Unit = {},
    ): DesktopPreparedRuntimeProcess = captured.withSnapshot { config, resources ->
        prepareCaptured(config, resources, logFile, onProgress, captured.mutableResources, scopeProvider)
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

    private fun admissionFailure(failure: Throwable, retained: AutoCloseable? = null): DesktopWindowsRuntimeFailure {
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

    /** Ordinary-owner admission surrounds authorization and the helper's preparation acknowledgment. */
    internal fun withNativeOwnerAdmission(native: WindowsAdmissionNative,
                                         prepare: (String) -> DesktopPreparedRuntimeProcess): DesktopPreparedRuntimeProcess {
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
                                scopeProvider: DesktopWindowsRuntimeResourceScopeProvider? = null): DesktopPreparedRuntimeProcess {
        if (mutableResources.isNotEmpty()) {
            if (scopeProvider == null) throw DesktopWindowsRuntimeFailure("UNAVAILABLE",
                stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
        }
        check(com.sun.jna.Platform.isWindows())
        check(Native.POINTER_SIZE == 8) { "UNSUPPORTED" }
        // The retained native owner image and runtime PE establish architecture; JVM properties
        // and an extraction cache cannot select either the executable or its elevated authority.
        val runtime = requireNotNull(javaClass.getResourceAsStream("/bin/windows-amd64/sing-box.exe")) {
            "UNAVAILABLE"
        }.use { it.readNBytes(192 * 1024 * 1024 + 1) }
        require(runtime.size in 1..192 * 1024 * 1024)
        requireAmd64Executable(runtime)
        require(config.isNotEmpty()) { "INVALID_ARGUMENT" }
        val digest = MessageDigest.getInstance("SHA-256").digest(runtime).joinToString("") { "%02x".format(it) }
        return withNativeOwnerAdmission(JnaWindowsInstallAdmission()) { _ ->
            val helper = try { DesktopWindowsVpnHelperAdmission.retain(digest, runtime.size.toLong()) }
                catch (failure: Throwable) { throw admissionFailure(failure) }
            var transferred = false
            var ownedChannel: DesktopWindowsVpnHelperChannel? = null
            var preparationFailure: Throwable? = null
            try {
                val api = Native.load("kernel32", Api::class.java)
                val scope = if (mutableResources.isEmpty()) null else scopeProvider?.current()
                    ?: throw DesktopWindowsRuntimeFailure("UNAVAILABLE", stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
                val resourceJob = scope?.let {
                    DesktopWindowsRuntimeResourceJob(UUID.randomUUID().toString(), it,
                        mutableResources.map { resource -> DesktopWindowsRuntimeResourceEntry(resource.id, resource.kind) }, helper.owner)
                }
                // Durable correlation precedes UAC and every native input. Its immutable native
                // owner tuple is exactly the tuple retained by the packaged helper admission.
                val reconciliation = resourceJob?.let {
                    DesktopWindowsRuntimeResourceReconciliation.retain(it, scopeProvider?.journals())
                }
                val name = "vpn-control-vpn-${UUID.randomUUID()}"
                val launch = ShellAPI.SHELLEXECUTEINFO().also {
                    it.fMask = 0x40
                    it.lpVerb = "runas"
                    it.lpFile = helper.executable
                    it.lpParameters = helper.parameters(name)
                    it.nShow = 0
                }
                // Both channels and every candidate/runtime owner are allocated before UAC.
                // The native channel creates its empty job inside the covered callback.
                val nativeChannel = NativeChannel(api, name)
                val channel = DesktopWindowsVpnHelperChannel(nativeChannel, helper)
                ownedChannel = channel
                var stage = DesktopWindowsRuntimePreparationStage.AUTHORIZATION
                desktopWindowsPrepareFixedHelper(channel, logFile, reconciliation,
                    stage = { stage }, authorizeAndPrepare = {
                        nativeChannel.createJob()
                        onProgress(stage)
                        // The callback captures its output even when returning from JNA throws.
                        // Cleanup owns that retained object, never a process rediscovered by PID.
                        val accepted = desktopWindowsRetainAuthorizedHelper(
                            authorize = { Shell32.INSTANCE.ShellExecuteEx(launch) },
                            capturedProcess = { launch.hProcess }, retain = nativeChannel::adoptBroker)
                        val process = launch.hProcess
                        if (!accepted) throw launchFailure(Kernel32.INSTANCE.GetLastError())
                        val broker = process ?: throw DesktopWindowsRuntimeFailure("UNAVAILABLE",
                            stage = DesktopWindowsRuntimePreparationStage.AUTHORIZATION)
                        stage = DesktopWindowsRuntimePreparationStage.HELPER_CONNECTION
                        onProgress(stage)
                        val pipe = nativeChannel.connect()
                        stage = DesktopWindowsRuntimePreparationStage.PEER_IDENTITY
                        onProgress(stage)
                        val brokerPid = Kernel32.INSTANCE.GetProcessId(broker)
                        val server = IntByReference()
                        check(api.GetNamedPipeServerProcessId(pipe, server) && server.value == brokerPid) { "PERMISSION_DENIED" }
                        helper.verifyStartedProcess(broker)
                        stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS
                        onProgress(stage)
                        nativeChannel.initialize(runtime, config, resources, resourceJob, mutableResources) {
                            stage = DesktopWindowsRuntimePreparationStage.CHILD_CREATED
                            onProgress(stage)
                        }
                        stage = DesktopWindowsRuntimePreparationStage.READY
                        onProgress(stage)
                    }).also { transferred = true }
            } catch (failure: Throwable) {
                preparationFailure = failure
                if (failure is DesktopWindowsRuntimeFailure &&
                    (failure.unresolvedRuntime != null || failure.retainedAdmission != null)) transferred = true
                throw failure
            } finally {
                if (!transferred) {
                    val pending = ownedChannel ?: helper
                    try { pending.close() }
                    catch (cleanup: Throwable) { throw admissionFailure(preparationFailure ?: cleanup, pending) }
                }
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

    internal fun command(name: String, pid: Long, creation: Long, sid: String, digest: String): String =
        DesktopWindowsVpnHelperAdmission.arguments(name, DesktopWindowsRuntimeResourceNativeOwner(pid, creation, sid), digest)

    internal fun commandParameters(executable: String, capturedCommand: String): String {
        require(executable.isNotEmpty() && '\u0000' !in executable && capturedCommand.all { it.code in 1..127 })
        if (windowsInstallArgument(executable).length.toLong() + capturedCommand.length + 2 > 32767)
            throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED", stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
        return capturedCommand
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

    private class NativeChannel(private val api: Api, private val pipeName: String) : DesktopWindowsPreparedRuntimeChannel {
        private var broker: WinNT.HANDLE? = null
        private var ownedJob: DesktopWindowsNativeJob? = null
        private val job: DesktopWindowsNativeJob get() = checkNotNull(ownedJob)
        fun createJob() { check(ownedJob == null); ownedJob = DesktopWindowsNativeJob.create() }
        fun adoptBroker(process: WinNT.HANDLE) { check(broker == null); broker = process }
        override var childPid: Long = 0; private set
        private var pipe: WinNT.HANDLE? = null
        private var pending = DesktopWindowsRuntimeStatus(true)
        private var closed = false
        private var pipeClosed = false
        private var committed = false
        fun connect(): WinNT.HANDLE = connect(api, pipeName, checkNotNull(broker)).also { pipe = it }
        fun initialize(runtime: ByteArray, configuration: String, resources: List<DesktopWindowsCapturedResource>,
                       resourceJob: DesktopWindowsRuntimeResourceJob?,
                       mutableResources: List<DesktopWindowsRuntimeResource>, childCreated: () -> Unit) {
            val preparation = resourceJob?.let { job ->
                ByteArrayOutputStream().also { output ->
                    DesktopWindowsRuntimeResourceProtocol.writePreparation(job, mutableResources, output::write)
                }.toByteArray().also { bytes -> require(bytes.size in 1..MAX_RESOURCE_PREPARATION_BYTES) }
            }
            // Opcode 4 remains byte-for-byte compatible with immutable-only helpers. Mutable
            // candidates use opcode 5, which requires the authenticated resource envelope.
            mutableProtocol = preparation != null
            write(integer(if (preparation == null) 4 else 5))
            write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(job.handleValue).array())
            if (preparation != null) {
                write(integer(preparation.size))
                write(preparation)
            }
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
            val result = read(1).single().toInt()
            when (result) {
                0 -> Unit
                1 -> throw DesktopWindowsRuntimeFailure("INVALID_ARGUMENT")
                2 -> throw DesktopWindowsRuntimeFailure("PERMISSION_DENIED")
                3 -> throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED")
                // Legacy helpers and generic native IO both use 4. It safely fails preparation
                // before B can run, but does not establish which side lacked the v5 contract.
                4 -> throw DesktopWindowsRuntimeFailure("UNAVAILABLE")
                5 -> throw DesktopWindowsRuntimeFailure("INCOMPATIBLE_PROTOCOL")
                6 -> throw DesktopWindowsRuntimeFailure("CONFLICT")
                7 -> throw DesktopWindowsRuntimeFailure("PERSISTENCE_FAILED")
                8 -> throw DesktopWindowsRuntimeFailure("UNSUPPORTED")
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
            if (broker == null) return ownedJob?.isEmpty() != false // No peer input/job duplication occurred.
            // Cancellation can arrive before the fixed helper finishes native admission.
            // Open and immediately close its pipe when ready; no input is sent before peer admission.
            if (pipe == null && !closed) {
                val candidate = api.CreateFileW(WString("\\\\.\\pipe\\$pipeName"),
                    0xc0000000.toInt(), 0, null, 3, 0x40110000, null)
                if (candidate != WinBase.INVALID_HANDLE_VALUE) pipe = candidate
            }
            closePipe()
            job.terminate()
            // Waiting for the exact helper also prevents a later suspended child appearing after
            // an initially empty job was observed. Never depend on elevation-token process rights.
            return Kernel32.INSTANCE.WaitForSingleObject(broker, 10000) == 0 && job.isEmpty()
        }
        @Synchronized override fun status(): DesktopWindowsRuntimeStatus {
            if (!pending.running) return pending.also { pending = it.copy(log = byteArrayOf()) }
            return exchange(0)
        }
        @Synchronized override fun stop(force: Boolean) { pending = exchange(if (force) 2 else 1) }
        override fun childExited() = closed || if (broker == null) ownedJob?.isEmpty() != false else
            (Kernel32.INSTANCE.WaitForSingleObject(broker, 0) == 0 && job.isEmpty())
        private fun exchange(command: Int): DesktopWindowsRuntimeStatus {
            check(!closed)
            write(byteArrayOf(command.toByte()))
            return DesktopWindowsRuntimeResourceProtocol.readStatus(mutableProtocol, ::read)
                .also { pending = it.copy(log = byteArrayOf()) }
        }
        private var mutableProtocol = false
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
            val process = broker
            check((process == null || Kernel32.INSTANCE.WaitForSingleObject(process, 10000) == 0) &&
                ownedJob?.isEmpty() != false) { "OUTCOME_UNKNOWN" }
            closePipe()
            ownedJob?.close()
            if (process != null) check(Kernel32.INSTANCE.CloseHandle(process)) { "OUTCOME_UNKNOWN" }
            closed = true
        }
    }
    private const val MAX_RESOURCE_PREPARATION_BYTES = 8 * 1024 * 1024
    private interface Api : StdCallLibrary {
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
