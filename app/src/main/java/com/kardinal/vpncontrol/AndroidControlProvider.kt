package com.kardinal.vpncontrol

import android.Manifest
import android.content.ContentProvider
import android.content.ContentProviderOperation
import android.content.ContentProviderResult
import android.content.ContentValues
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.system.ErrnoException
import android.system.OsConstants
import java.io.FileNotFoundException
import java.util.concurrent.atomic.AtomicInteger

/**
 * ADB transport: call create; write JSON to requests/<opaque id>; poll call status;
 * read the completed JSON from results/<opaque id>; call discard to release it.
 * All request contents travel through descriptors, never command arguments/extras.
 */
class AndroidControlProvider : ContentProvider() {
    private val openDescriptors = AtomicInteger()
    private val callbackHandler by lazy {
        Handler(HandlerThread("control-streams").apply { start() }.looper)
    }
    private val authority get() = requireNotNull(context).packageName + ".control"
    private val owner get() = AndroidApplicationOwner.get(requireNotNull(context))

    override fun onCreate(): Boolean = true

    private fun authorize(): Int {
        val uid = Binder.getCallingUid()
        AndroidControlAccess.authorize(
            uid, Process.myUid(),
            requireNotNull(context).checkPermission(Manifest.permission.DUMP, Binder.getCallingPid(), uid) == PackageManager.PERMISSION_GRANTED,
        )
        return uid
    }

    override fun call(authority: String, method: String, arg: String?, extras: Bundle?): Bundle {
        authorize()
        require(authority == this.authority) { "INVALID_ARGUMENT" }
        return call(method, arg, extras)
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val uid = authorize()
        require(extras == null || extras.isEmpty) { "INVALID_ARGUMENT" }
        return when (method) {
            "create" -> {
                require(arg == null) { "INVALID_ARGUMENT" }
                val id = owner.controlTransfers.create(uid)
                Bundle().apply {
                    putString("id", id)
                    putString("controllerId", owner.controlReader.controllerId)
                    putString("requestUri", "content://$authority/requests/$id")
                    putString("resultUri", "content://$authority/results/$id")
                }
            }
            "status" -> Bundle().apply {
                putString("state", owner.controlTransfers.phase(AndroidControlAccess.opaqueId(requireNotNull(arg)), uid))
            }
            "interaction" -> Bundle().apply {
                val operation = AndroidControlAccess.opaqueId(requireNotNull(arg))
                val token = owner.interactions.tokenFor(operation)
                putString("state", if (token == null) "none" else "waiting")
                if (token != null) putString("token", token)
            }
            "discard" -> {
                owner.controlTransfers.remove(AndroidControlAccess.opaqueId(requireNotNull(arg)), uid)
                Bundle.EMPTY
            }
            else -> throw IllegalArgumentException("UNSUPPORTED")
        }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val uid = authorize()
        val (kind, id) = AndroidControlAccess.parseUri(uri.toString(), authority)
        val writing = kind == "requests" && mode == "w"
        require(writing || kind == "results" && mode == "r") { "INVALID_ARGUMENT" }
        val transfers = owner.controlTransfers
        if (openDescriptors.incrementAndGet() > 8) {
            openDescriptors.decrementAndGet()
            throw FileNotFoundException("BUSY")
        }
        var claimedWrite = false
        try {
            if (writing) {
                transfers.beginWrite(id, uid)
                claimedWrite = true
            } else transfers.resultSize(id, uid)
            val callback = object : ProxyFileDescriptorCallback() {
                private var invalid = false
                override fun onGetSize(): Long = checked {
                    if (writing) { transfers.phase(id, uid); 0L } else transfers.resultSize(id, uid)
                }
                override fun onRead(offset: Long, size: Int, data: ByteArray): Int = checked {
                    check(!writing)
                    transfers.read(id, uid, offset, size, data)
                }
                override fun onWrite(offset: Long, size: Int, data: ByteArray): Int = checked {
                    check(writing)
                    transfers.append(id, uid, offset, data, size)
                }
                override fun onFsync() { checked { transfers.phase(id, uid) } }
                override fun onRelease() {
                    openDescriptors.decrementAndGet()
                    if (!writing) return
                    if (invalid) {
                        runCatching { transfers.remove(id, uid) }
                        return
                    }
                    val bytes = runCatching { transfers.finishWrite(id, uid) }.getOrNull() ?: return
                    owner.commands.launch {
                        try {
                            val response = owner.controlReader.execute(bytes, id)
                            // Expired/discarded transfers cannot be resurrected. The reader
                            // already bounds output and correlates all command failures.
                            runCatching { transfers.complete(id, uid, response) }
                        } finally {
                            bytes.fill(0)
                        }
                    }
                }
                private fun <T> checked(action: () -> T): T = try {
                    check(!invalid)
                    action()
                } catch (_: Exception) {
                    invalid = true
                    throw ErrnoException("control", OsConstants.EIO)
                }
            }
            // Authentication above precedes both clearing identity and any asynchronous work.
            val token = Binder.clearCallingIdentity()
            try {
                return requireNotNull(context).getSystemService(StorageManager::class.java).openProxyFileDescriptor(
                    if (writing) ParcelFileDescriptor.MODE_WRITE_ONLY else ParcelFileDescriptor.MODE_READ_ONLY,
                    callback, callbackHandler,
                )
            } finally {
                Binder.restoreCallingIdentity(token)
            }
        } catch (error: Exception) {
            openDescriptors.decrementAndGet()
            if (claimedWrite) runCatching { transfers.remove(id, uid) }
            throw FileNotFoundException(if (error is SecurityException) "PERMISSION_DENIED" else "UNAVAILABLE")
        }
    }

    override fun getType(uri: Uri): String {
        authorize()
        AndroidControlAccess.parseUri(uri.toString(), authority)
        return "application/json"
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = unsupported()
    override fun insert(uri: Uri, values: ContentValues?): Uri? = unsupported()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = unsupported()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = unsupported()
    override fun bulkInsert(uri: Uri, values: Array<out ContentValues>): Int = unsupported()
    override fun applyBatch(operations: ArrayList<ContentProviderOperation>): Array<ContentProviderResult> = unsupported()
    override fun canonicalize(url: Uri): Uri? = unsupported()
    override fun uncanonicalize(url: Uri): Uri? = unsupported()
    override fun refresh(uri: Uri, args: Bundle?, cancellationSignal: android.os.CancellationSignal?): Boolean = unsupported()
    override fun getStreamTypes(uri: Uri, mimeTypeFilter: String): Array<String>? = unsupported()
    override fun getTypeAnonymous(uri: Uri): String? = unsupported()

    private fun unsupported(): Nothing {
        authorize()
        throw UnsupportedOperationException("UNSUPPORTED")
    }
}
