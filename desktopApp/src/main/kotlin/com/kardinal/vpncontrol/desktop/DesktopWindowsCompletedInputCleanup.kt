package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.security.MessageDigest

/** Existing-object capabilities only. None launches an actor, publishes success or grants privilege. */
internal interface WindowsCompletedInputNative : WindowsDeniedInputNative {
    /** Five fixed leaves plus one overflow witness; denial's existing two-leaf bound is unchanged. */
    fun completedInputChildren(path: String): List<String>
    fun completedInputProtectedDacl(handle: WindowsInstallNative.Handle): Boolean
    /** Retains the inspected process (if present); only an exact exited/replaced original is accepted. */
    fun openInputActor(pid: Long): WindowsCompletedInputActor
}

internal interface WindowsCompletedInputActor : AutoCloseable {
    fun requireOriginalClosed(creationFileTime: Long)
}

/** Native-directory identity is available only from the retained Windows protected backend. */
internal interface WindowsInputCustodyDirectory : DesktopInstallJobBackend.Directory {
    fun inputCustodyNativeId(): String
    fun openInputCustody(): DesktopInstallJobBackend.File
}

internal class DesktopWindowsProtectedInputCustody(
    private val machine: WindowsInputCustodyDirectory,
    private val job: WindowsInputCustodyDirectory,
    private val file: DesktopInstallJobBackend.File,
    private val original: ByteArray,
) : AutoCloseable {
    val value = DesktopWindowsInputCustody.decode(original)
    fun revalidate(binding: DesktopInstallCorrelationRecord, expected: DesktopInstallJobReceipt, sid: String) {
        value.requireBinding(binding, expected, sid, binding.workspaceKey)
        require(machine.inputCustodyNativeId() == value.protectedMachineNativeId &&
            job.inputCustodyNativeId() == value.protectedJobNativeId) { "CONFLICT" }
        require(file.readBounded(DesktopWindowsInputCustody.MAX_BYTES).contentEquals(original)) { "CONFLICT" }
        val receipt = job.openFile(DesktopInstallJobNames.STATUS).use {
            DesktopInstallJobReceipt.decode(it.readBounded(DesktopInstallJobReceipt.MAX_BYTES))
        }
        require(receipt == expected) { "CONFLICT" }
    }
    override fun close() = file.close()

    companion object {
        /** All opened native handles are already owned by the caller's retryable handle facade. */
        fun open(native: WindowsDeniedInputNative, ancestry: WindowsAdmissionNative,
                 binding: DesktopInstallCorrelationRecord, holders: MutableList<AutoCloseable>): DesktopWindowsProtectedInputCustody {
            val backend = DesktopWindowsInstallJobBackend(native, ancestry)
            val root = backend.openRoot(backend.defaultRoot(), false) as WindowsInputCustodyDirectory
            holders += root
            val job = root.openJob(binding.jobId) as WindowsInputCustodyDirectory
            holders += job
            val file = job.openInputCustody()
            holders += file
            return DesktopWindowsProtectedInputCustody(root, job, file,
                file.readBounded(DesktopWindowsInputCustody.MAX_BYTES))
        }
    }
}

/** Ordinary serialized maintenance of one successful native job; protected evidence stays intact. */
internal class DesktopWindowsCompletedInputCleanup(
    inputRoot: () -> String,
    private val native: WindowsCompletedInputNative,
    private val ancestry: WindowsAdmissionNative,
    private val read: (DesktopInstallCorrelationRecord) -> DesktopInstallCorrelationRecovery,
    private val hasPending: () -> Boolean = { false },
) {
    constructor(inputRoot: String, native: WindowsCompletedInputNative, ancestry: WindowsAdmissionNative,
        read: (DesktopInstallCorrelationRecord) -> DesktopInstallCorrelationRecovery, hasPending: () -> Boolean = { false }) :
        this({ inputRoot }, native, ancestry, read, hasPending)
    private val root by lazy { DesktopWindowsInstallJobBackend.canonical(inputRoot()) }
    private val debt = mutableListOf<AutoCloseable>()
    @Synchronized fun blocksPreparation() = debt.isNotEmpty()
    @Synchronized fun reconcileHolders() = closeWindowsDeniedInputHolders(debt)

    @Synchronized fun release(record: DesktopInstallCorrelationRecovery): Result<Unit> = runCatching {
        require(!hasPending()) { "BUSY" }
        val binding = requireNotNull(record.binding)
        val receipt = requireNotNull(record.receipt)
        require(!record.notStarted && binding.receiptAuthority == DesktopInstallReceiptAuthority.MACHINE &&
            receipt.jobId == binding.jobId && receipt.phase == DesktopInstallJobPhase.SUCCEEDED && receipt.code == ControlCode.OK) { "OUTCOME_UNKNOWN" }
        fun current() {
            require(read(binding).copy(cleanupCode = null) == record.copy(cleanupCode = null)) { "CONFLICT" }
        }
        current()
        reconcileHolders().getOrThrow()
        withInputRoot { rootHandle, holders, api ->
            if (rootHandle == null) return@withInputRoot
            val path = root + "\\" + binding.jobId
            val job = openMissing(path, true, api) ?: return@withInputRoot
            val jobHolder = AutoCloseable { api.close(job) }; holders += jobHolder
            verify(job, true); linked(rootHandle, job)
            // Present legacy inputs without the new protected native custody remain unresolved.
            val proof = DesktopWindowsProtectedInputCustody.open(api, ancestry, binding, holders)
            fun revalidate() {
                current()
                proof.revalidate(binding, receipt, ancestry.currentSid())
                for (actor in listOf(proof.value.worker, proof.value.coordinator)) {
                    val process = native.openInputActor(actor.pid)
                    holders += process
                    process.requireOriginalClosed(actor.creationFileTime)
                }
            }
            revalidate()
            val custody = proof.value
            require(native.deniedInputIdentity(rootHandle) == custody.inputRootNativeId &&
                native.deniedInputIdentity(job) == custody.inputJobNativeId) { "CONFLICT" }
            val children = native.completedInputChildren(path)
            require(children.size <= 5 && children.distinct().size == children.size &&
                children.all { it in custody.files.map { leaf -> leaf.name } }) { "CONFLICT" }
            val opened = linkedMapOf<String, Pair<WindowsInstallNative.Handle, AutoCloseable>>()
            for (leaf in custody.files) {
                val handle = openMissing(path + "\\" + leaf.name, true, api) ?: continue
                val holder = AutoCloseable { api.close(handle) }; holders += holder
                opened[leaf.name] = handle to holder
                verify(handle, false); linked(job, handle)
                require(native.deniedInputIdentity(handle) == leaf.nativeId && native.inspect(handle).size == leaf.size) { "CONFLICT" }
                val digest = MessageDigest.getInstance("SHA-256")
                val bytes = ByteArray(8192); var length = 0L
                while (true) {
                    val count = native.readDeniedInputChunk(handle, length, bytes, bytes.size)
                    require(count in 0..bytes.size && count.toLong() <= leaf.size - length) { "CONFLICT" }
                    if (count == 0) break
                    digest.update(bytes, 0, count); length += count
                }
                require(length == leaf.size && native.inspect(handle).size == length &&
                    digest.digest().joinToString("") { "%02x".format(it) } == leaf.sha256 &&
                    native.deniedInputIdentity(handle) == leaf.nativeId) { "CONFLICT" }
                // A same-byte replacement is foreign. The named lookup shares delete solely
                // to coexist with our retained DELETE handle; it never requests deletion.
                val named = api.open(path + "\\" + leaf.name, WindowsInstallNative.INSPECT, true)
                val namedHolder = AutoCloseable { api.close(named) }; holders += namedHolder
                require(native.deniedInputIdentity(named) == leaf.nativeId) { "CONFLICT" }
                namedHolder.close(); holders.remove(namedHolder)
            }
            revalidate()
            verify(rootHandle, true); verify(job, true)
            require(native.deniedInputIdentity(rootHandle) == custody.inputRootNativeId &&
                native.deniedInputIdentity(job) == custody.inputJobNativeId) { "CONFLICT" }
            for (leaf in custody.files) opened[leaf.name]?.first?.let { handle ->
                verify(handle, false)
                require(native.deniedInputIdentity(handle) == leaf.nativeId) { "CONFLICT" }
            }
            // No recursion or discovery-driven deletion. A late foreign child prevents job removal.
            for (name in listOf("package.msi", "request.json", "commit.json", "worker-ready.json", "worker-result.json")) {
                opened[name]?.let { (handle, holder) ->
                    native.delete(handle); holder.close(); holders.remove(holder)
                }
            }
            native.delete(job); jobHolder.close(); holders.remove(jobHolder)
        }.getOrThrow()
        require(inputAbsent(binding)) { "PERSISTENCE_FAILED" }
    }.recoverCatching { throw IllegalStateException("PERSISTENCE_FAILED", it) }

    /** Precise final-child absence plus closed holders; inaccessible ancestors never count. */
    @Synchronized fun inputAbsent(binding: DesktopInstallCorrelationRecord): Boolean = runCatching {
        if (blocksPreparation()) return@runCatching false
        var absent = false
        withInputRoot { rootHandle, holders, api ->
            if (rootHandle == null) { absent = true; return@withInputRoot }
            val job = openMissing(root + "\\" + binding.jobId, false, api)
            if (job == null) absent = true else {
                holders += AutoCloseable { api.close(job) }
                verify(job, true); linked(rootHandle, job)
            }
        }.getOrThrow()
        absent && !blocksPreparation()
    }.getOrDefault(false)

    private fun openMissing(path: String, delete: Boolean, api: WindowsDeniedInputNative): WindowsInstallNative.Handle? = try {
        if (delete) api.openDeniedInput(path) else api.open(path, WindowsInstallNative.INSPECT, false)
    } catch (failure: WindowsInstallNativeFailure) {
        if (failure.code in setOf(2, 3)) null else throw failure
    }
    private fun <T> withInputRoot(block: (WindowsInstallNative.Handle?, MutableList<AutoCloseable>, WindowsDeniedInputNative) -> T): Result<T> {
        val handles = DesktopWindowsDeniedInputHandles(native)
        val api = handles.native
        val holders = mutableListOf<AutoCloseable>(handles)
        var result = runCatching {
            val sid = ancestry.currentSid()
            val pins = DesktopWindowsTransferPins.open(root.substringBeforeLast('\\'), sid, api, ancestry)
            holders += pins
            val parent = openMissing(root, false, api)
            if (parent != null) {
                holders += AutoCloseable { api.close(parent) }
                verify(parent, true); linked(pins.parentHandle, parent)
            }
            block(parent, holders, api)
        }
        val close = closeWindowsDeniedInputHolders(holders)
        if (close.isFailure) {
            debt.addAll(holders)
            val original = result.exceptionOrNull()
            if (original != null) { original.addSuppressed(close.exceptionOrNull()!!); result = Result.failure(original) }
            else result = Result.failure(close.exceptionOrNull()!!)
        }
        return result
    }
    private fun linked(parent: WindowsInstallNative.Handle, child: WindowsInstallNative.Handle) {
        require(native.deniedInputCanonicalPath(child).substringBeforeLast('\\') ==
            native.deniedInputCanonicalPath(parent).trimEnd('\\')) { "CONFLICT" }
    }
    private fun verify(handle: WindowsInstallNative.Handle, directory: Boolean) {
        require(native.deniedInputPersistentAcl(handle) && native.completedInputProtectedDacl(handle)) { "PERMISSION_DENIED" }
        val info = native.inspect(handle); val sid = ancestry.currentSid()
        require(info.disk && info.directory == directory && info.attributes and 0x400 == 0 && info.reparseTag == 0 &&
            info.owner == sid && (directory || info.links == 1)) { "PERMISSION_DENIED" }
        val acl = requireNotNull(info.dacl); require(acl.isNotEmpty()) { "PERMISSION_DENIED" }
        for (ace in acl) {
            require(ace.type in 0..1 && ace.flags and 0x1f.inv() == 0) { "PERMISSION_DENIED" }
            if (ace.type == 1 || ace.sid == sid) continue
            require(ace.sid in setOf("S-1-5-32-544", "S-1-5-18") && ace.mask and 0xA01200A9.toInt().inv() == 0) { "PERMISSION_DENIED" }
        }
    }
}
