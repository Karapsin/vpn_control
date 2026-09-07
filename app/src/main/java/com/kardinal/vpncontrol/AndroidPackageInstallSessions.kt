package com.kardinal.vpncontrol

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.AtomicFile
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject

/** PackageInstaller owns staged APK bytes. Private receipts never imply installation from version. */
internal class AndroidPackageInstallSessions private constructor(private val context: Context) {
    private val installer get() = context.packageManager.packageInstaller
    private val directory = File(context.noBackupFilesDir, "control-install-sessions").apply {
        check(isDirectory || mkdirs())
    }
    private val changed = MutableStateFlow(0L)
    private val receipts = mutableMapOf<String, AndroidInstallSessionLifecycle>()
    // The framework's lookup table is weak. Keep callbacks alive while this owner
    // exists; explicit recovery refreshes the exact session after process death.
    private val confirmations = mutableMapOf<String, PendingIntent>()
    private var receiptLoadUnavailable = false
    private val cleanedTerminal = mutableSetOf<String>()
    @Volatile private var observer: ((AppInstallSessionStatus?) -> Unit)? = null
    @Synchronized fun observe(block: (AppInstallSessionStatus?) -> Unit) {
        observer = block
        block(if (receiptLoadUnavailable) AppInstallSessionStatus("unavailable", AndroidInstallSessionPhase.UNKNOWN, "", false)
            else latest()?.let(::uiStatus))
    }

    init {
        val names = directory.list()?.toList()
        val loaded = AndroidInstallReceiptRecovery.load(names.orEmpty()) { base ->
            AtomicFile(File(directory, base)).openRead().use { input ->
                require(input.channel.size() <= 65536) { "INSTALL_RECEIPT_INVALID" }
                decode(JSONObject(input.bufferedReader().readText()))
            }
        }
        receiptLoadUnavailable = names == null || loaded.unavailable
        loaded.receipts.forEach { receipts[it.id] = lifecycle(it) }
        cleanupTerminal()
    }

    private fun lifecycle(value: AndroidInstallSessionReceipt) = AndroidInstallSessionLifecycle(value, ::persist) { next ->
        observer?.invoke(uiStatus(next))
    }
    private fun persist(next: AndroidInstallSessionReceipt) {
        val atomic = AtomicFile(File(directory, "${next.id}.json"))
        val output = atomic.startWrite()
        try {
            output.write(encode(next).toString().toByteArray(Charsets.UTF_8))
            atomic.finishWrite(output)
        } catch (error: Exception) { atomic.failWrite(output); throw error }
    }

    @Synchronized fun recover(): AndroidUpdateInstallControl.Pinned? {
        check(!receiptLoadUnavailable) { "INSTALL_RECOVERY_UNAVAILABLE" }
        // Only a journal known to precede commit authorizes reclaiming interrupted staging.
        receipts.values.filter { it.snapshot().phase == AndroidInstallSessionPhase.PREPARING }.toList().forEach { item ->
            val receipt = item.snapshot()
            val matches = installer.mySessions.filter { info ->
                info.originatingUri == origin(receipt.id) && info.installerPackageName == context.packageName &&
                    info.appPackageName == context.packageName && info.mode == PackageInstaller.SessionParams.MODE_FULL_INSTALL &&
                    (receipt.sessionId < 0 || receipt.sessionId == info.sessionId)
            }
            check(matches.size <= 1) { "INSTALL_RECOVERY_AMBIGUOUS" }
            matches.singleOrNull()?.let { installer.abandonSession(it.sessionId) }
            // An explicitly recorded session that no longer matches is not safe to delete.
            check(receipt.sessionId < 0 || installer.getSessionInfo(receipt.sessionId) == null) { "INSTALL_RECOVERY_UNAVAILABLE" }
            AtomicFile(File(directory, "${receipt.id}.json")).delete()
            receipts.remove(receipt.id)
            observer?.invoke(latest()?.let(::uiStatus))
        }
        val pending = receipts.values.filter { !it.snapshot().terminal }
        if (pending.isEmpty()) return null
        check(pending.size == 1) { "INSTALL_RECOVERY_AMBIGUOUS" }
        val item = pending.single()
        val state = item.snapshot()
        if (state.phase == AndroidInstallSessionPhase.UNKNOWN ||
            installer.getSessionInfo(state.sessionId) == null) {
            item.reconcile(false)
            error("INSTALL_OUTCOME_UNKNOWN")
        }
        return pin(item)
    }

    suspend fun stage(file: File, asset: UpdateAsset, build: Int): AndroidUpdateInstallControl.Pinned = withContext(Dispatchers.IO) {
        synchronized(this@AndroidPackageInstallSessions) {
            check(!receiptLoadUnavailable) { "INSTALL_RECOVERY_UNAVAILABLE" }
            val legacy = File(context.filesDir, "control-installs").listFiles()?.size ?: 0
            check(receipts.values.count { !it.snapshot().terminal || it.snapshot().id !in cleanedTerminal } + legacy < 8 &&
                receipts.size < 40) { "INSTALL_RETENTION_FULL" }
            check(receipts.values.none { !it.snapshot().terminal }) { "INSTALL_RECOVERY_REQUIRED" }
        }
        val receipt = AndroidInstallSessionReceipt(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
            -1, asset.displayVersion, build, asset.sha256, asset.sizeBytes,
            AndroidInstallSessionPhase.PREPARING, signers = installedSigners())
        val item = lifecycle(receipt)
        persist(receipt)
        synchronized(this@AndroidPackageInstallSessions) {
            receipts[receipt.id] = item
            observer?.invoke(uiStatus(receipt))
        }
        val parameters = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            setSize(asset.sizeBytes)
            setOriginatingUri(origin(receipt.id))
            if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
        }
        var sessionId = -1
        var tracked = false
        try {
            sessionId = installer.createSession(parameters)
            item.sessionCreated(sessionId)
            installer.openSession(sessionId).use { session ->
                session.openWrite("base.apk", 0, asset.sizeBytes).use { output ->
                    file.inputStream().use { input ->
                        val digest = MessageDigest.getInstance("SHA-256")
                        val buffer = ByteArray(65536)
                        var count = 0L
                        while (true) {
                            val size = input.read(buffer)
                            if (size < 0) break
                            count += size
                            require(count <= asset.sizeBytes)
                            digest.update(buffer, 0, size)
                            output.write(buffer, 0, size)
                        }
                        require(count == asset.sizeBytes && hex(digest.digest()) == asset.sha256)
                    }
                    session.fsync(output)
                }
            }
            item.staged()
            tracked = true
            pin(item)
        } finally {
            // Only this freshly created, uncommitted session can be abandoned on staging failure.
            if (!tracked && sessionId >= 0) {
                installer.abandonSession(sessionId)
                synchronized(this@AndroidPackageInstallSessions) {
                    AtomicFile(File(directory, "${receipt.id}.json")).delete()
                    receipts.remove(receipt.id)
                }
            }
        }
    }

    private fun pin(item: AndroidInstallSessionLifecycle) = object : AndroidUpdateInstallControl.Pinned {
        @Volatile private var launched = false
        private var preparedConfirmation: PendingIntent? = null
        override val version get() = item.snapshot().version
        override fun handedOff() = launched
        override fun snapshot() = item.snapshot().let { receipt ->
            AndroidUpdateInstallControl.PinnedState(uiStatus(receipt), publicReceipt(receipt))
        }
        override suspend fun verify() = withContext(Dispatchers.IO) {
            val receipt = item.snapshot()
            require(receipt.signers.isNotEmpty() && receipt.signers == installedSigners())
            validateSession(item, receipt)
            if (receipt.phase == AndroidInstallSessionPhase.STAGED) installer.openSession(receipt.sessionId).use { session ->
                session.openRead("base.apk").use { input ->
                    val digest = MessageDigest.getInstance("SHA-256")
                    val buffer = ByteArray(65536)
                    var count = 0L
                    while (true) {
                        val size = input.read(buffer)
                        if (size < 0) break
                        count += size
                        require(count <= receipt.byteCount)
                        digest.update(buffer, 0, size)
                    }
                    require(count == receipt.byteCount && hex(digest.digest()) == receipt.sha256)
                }
            }
        }
        override suspend fun prepareDispatch() {
            check(context.packageManager.canRequestPackageInstalls())
            preparedConfirmation = AndroidInstallConfirmationRecovery(item, ::confirmationFor,
                { validateSession(item, it) }, ::commitExistingSession,
                { ready -> withTimeout(30_000) { changed.first { ready() } }; Unit }).prepare()
        }
        override fun dispatch(launcher: (Intent) -> Unit) {
            val confirmation = checkNotNull(preparedConfirmation) { "INSTALL_CONFIRMATION_UNAVAILABLE" }
            // The protected interaction Activity launches this exact immutable OS capability.
            launcher(Intent().putExtra(INSTALL_CONFIRMATION, confirmation.intentSender))
            launched = true
            item.handedOff()
        }
        override fun release(handedOff: Boolean) {
            if (!item.canAbandon()) return
            val receipt = item.snapshot()
            installer.abandonSession(receipt.sessionId)
            synchronized(this@AndroidPackageInstallSessions) {
                AtomicFile(File(directory, "${receipt.id}.json")).delete()
                receipts.remove(receipt.id)
                observer?.invoke(latest()?.let(::uiStatus))
            }
        }
    }

    private fun validateSession(item: AndroidInstallSessionLifecycle, receipt: AndroidInstallSessionReceipt) {
        val info = installer.getSessionInfo(receipt.sessionId)
        if (info == null) { item.reconcile(false); error("INSTALL_OUTCOME_UNKNOWN") }
        check(info.sessionId == receipt.sessionId && info.originatingUri == origin(receipt.id) &&
            info.installerPackageName == context.packageName && info.appPackageName == context.packageName &&
            info.mode == PackageInstaller.SessionParams.MODE_FULL_INSTALL) { "INSTALL_RECOVERY_UNAVAILABLE" }
    }

    private fun commitExistingSession(receipt: AndroidInstallSessionReceipt) {
        val callback = Intent(context, AndroidInstallSessionReceiver::class.java).apply {
            data = Uri.parse("vpn-control-install://${receipt.id}/${receipt.nonce}")
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
        val sender = PendingIntent.getBroadcast(context, receipt.sessionId, callback, flags)
        installer.openSession(receipt.sessionId).use { it.commit(sender.intentSender) }
    }

    @Synchronized private fun confirmationFor(receipt: AndroidInstallSessionReceipt): PendingIntent? {
        if (receipt.terminal) return null
        confirmations[receipt.id]?.let { return it }
        val filter = receipt.confirmation?.let { Intent.parseUri(it, Intent.URI_INTENT_SCHEME) } ?: return null
        return PendingIntent.getActivity(context, receipt.sessionId, filter,
            PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE)?.also { confirmations[receipt.id] = it }
    }

    @Synchronized fun receive(intent: Intent) {
        val data = intent.data ?: return
        if (data.scheme != "vpn-control-install") return
        val item = receipts[data.host] ?: return
        val receipt = item.snapshot()
        if (data.pathSegments.singleOrNull() != receipt.nonce ||
            intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1) != receipt.sessionId || receipt.terminal) return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, Int.MIN_VALUE)
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirmation = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                confirmation.identifier = receipt.id
                // Retain every OS extra in an immutable capability. It may need a
                // fresh exact-session callback after our process and its refs disappear.
                confirmations[receipt.id] = PendingIntent.getActivity(context, receipt.sessionId, confirmation,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                item.callback(receipt.sessionId, receipt.nonce, AndroidInstallSessionPhase.AWAITING_CONFIRMATION,
                    confirmation.cloneFilter().toUri(Intent.URI_INTENT_SCHEME))
            }
            PackageInstaller.STATUS_SUCCESS -> item.callback(receipt.sessionId, receipt.nonce, AndroidInstallSessionPhase.INSTALLED)
            PackageInstaller.STATUS_FAILURE_ABORTED -> item.callback(receipt.sessionId, receipt.nonce, AndroidInstallSessionPhase.CANCELLED)
            in PackageInstaller.STATUS_FAILURE..PackageInstaller.STATUS_FAILURE_TIMEOUT ->
                item.callback(receipt.sessionId, receipt.nonce, AndroidInstallSessionPhase.FAILED)
            else -> return
        }
        cleanupTerminal()
        changed.value++
    }

    @Synchronized fun inspection(): Map<String, com.kardinal.vpncontrol.model.ControlValue> {
        val value = latest()
        return mapOf("installReceipt" to (value?.let { com.kardinal.vpncontrol.model.ControlValue.ObjectValue(publicReceipt(it)) }
            ?: com.kardinal.vpncontrol.model.ControlValue.Null),
            "installRecoveryUnavailable" to com.kardinal.vpncontrol.model.ControlValue.BooleanValue(receiptLoadUnavailable),
            "legacyInstallerPins" to com.kardinal.vpncontrol.model.ControlValue.IntegerValue(
                (File(context.filesDir, "control-installs").listFiles()?.size ?: 0).toLong()))
    }

    private fun latest() = receipts.values.map { it.snapshot() }
        .maxWithOrNull(compareBy<AndroidInstallSessionReceipt> { !it.terminal }.thenBy { it.createdAt }.thenBy { it.id })

    private fun cleanupTerminal() {
        receipts.values.map { it.snapshot() }.filter { it.terminal && it.id !in cleanedTerminal }.forEach { receipt ->
            if (AndroidInstallReceiptRecovery.cleanup(receipt, {
                val callback = Intent(context, AndroidInstallSessionReceiver::class.java).apply {
                    data = Uri.parse("vpn-control-install://${receipt.id}/${receipt.nonce}")
                }
                PendingIntent.getBroadcast(context, receipt.sessionId, callback, PendingIntent.FLAG_NO_CREATE or
                    (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0))?.cancel()
            }, {
                confirmations.remove(receipt.id)?.cancel()
                receipt.confirmation?.let { encoded ->
                    PendingIntent.getActivity(context, receipt.sessionId, Intent.parseUri(encoded, Intent.URI_INTENT_SCHEME),
                        PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE)?.cancel()
                }
            })) cleanedTerminal += receipt.id
        }
        // Retry failed capability cleanup on next callback/startup; never evict its only receipt.
        receipts.values.map { it.snapshot() }.filter { it.terminal }.sortedByDescending { it.createdAt }
            .drop(32).filter { it.id in cleanedTerminal }.forEach { expired ->
                AtomicFile(File(directory, "${expired.id}.json")).delete()
                if (!File(directory, "${expired.id}.json").exists() && !File(directory, "${expired.id}.json.bak").exists()) {
                    receipts.remove(expired.id)
                    cleanedTerminal.remove(expired.id)
                }
            }
    }

    @Suppress("DEPRECATION")
    private fun installedSigners(): Set<String> = context.packageManager.getPackageInfo(context.packageName,
        PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners.orEmpty()
        .map { hex(MessageDigest.getInstance("SHA-256").digest(it.toByteArray())) }.toSet()

    companion object {
        const val INSTALL_CONFIRMATION = "com.kardinal.vpncontrol.INSTALL_CONFIRMATION"
        @Volatile private var instance: AndroidPackageInstallSessions? = null
        fun get(context: Context): AndroidPackageInstallSessions = instance ?: synchronized(this) {
            instance ?: AndroidPackageInstallSessions(context.applicationContext).also { instance = it }
        }
        private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
        private fun origin(id: String): Uri = Uri.parse("vpn-control-install-source://$id")
        private fun uiStatus(value: AndroidInstallSessionReceipt) = AppInstallSessionStatus(value.id, value.phase,
            value.version, value.phase == AndroidInstallSessionPhase.STAGED ||
                value.confirmation != null && !value.terminal)
        private fun publicReceipt(value: AndroidInstallSessionReceipt): Map<String, com.kardinal.vpncontrol.model.ControlValue> =
            mapOf("installReceiptId" to com.kardinal.vpncontrol.model.ControlValue.Text(value.id),
                "installSessionId" to com.kardinal.vpncontrol.model.ControlValue.IntegerValue(value.sessionId.toLong()),
                "installPhase" to com.kardinal.vpncontrol.model.ControlValue.Text(value.phase.name.lowercase()),
                "installed" to (if (value.terminal) com.kardinal.vpncontrol.model.ControlValue.BooleanValue(
                    value.phase == AndroidInstallSessionPhase.INSTALLED) else com.kardinal.vpncontrol.model.ControlValue.Null))
        private fun encode(value: AndroidInstallSessionReceipt) = JSONObject().apply {
            put("id", value.id); put("nonce", value.nonce); put("sessionId", value.sessionId)
            put("version", value.version); put("build", value.build); put("sha256", value.sha256)
            put("byteCount", value.byteCount); put("phase", value.phase.name)
            put("createdAt", value.createdAt)
            put("confirmation", value.confirmation ?: JSONObject.NULL)
            put("signers", org.json.JSONArray(value.signers.sorted()))
        }
        private fun decode(value: JSONObject): AndroidInstallSessionReceipt {
            val id = value.getString("id")
            require(UUID.fromString(id).toString() == id)
            val signers = value.getJSONArray("signers")
            return AndroidInstallSessionReceipt(id, value.getString("nonce"), value.getInt("sessionId"),
                value.getString("version"), value.getInt("build"), value.getString("sha256"),
                value.getLong("byteCount"), AndroidInstallSessionPhase.valueOf(value.getString("phase")),
                if (value.isNull("confirmation")) null else value.getString("confirmation"),
                (0 until signers.length()).map { signers.getString(it) }.toSet(), value.optLong("createdAt", 0))
        }
    }
}

/** No intent filter/export: only our private status PendingIntent grants callback authority. */
class AndroidInstallSessionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        try { AndroidPackageInstallSessions.get(context).receive(intent) }
        catch (_: Exception) {
            android.util.Log.w("ControlInstall", "INSTALL_RECEIPT_UNAVAILABLE")
        }
    }
}
