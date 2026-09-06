package com.kardinal.vpncontrol

import android.app.KeyguardManager
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.launch

/** DUMP-protected entry, further authorized by an authenticated provider-issued capability. */
class AndroidControlInteractionActivity : ComponentActivity() {
    private val owner by lazy { AndroidApplicationOwner.get(applicationContext) }
    private var token: String? = null
    private var session: String? = null
    private var permissionReturned = false
    private var installDispatching = false
    private val installPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        permissionReturned = true
        // The settings screen does not report permission through its Activity result code.
        continueWhenVisible()
    }
    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        permissionReturned = true
        if (result.resultCode != RESULT_OK || runCatching { VpnService.prepare(this) == null }.getOrDefault(false).not()) resolve(ControlCode.PERMISSION_DENIED)
        else continueWhenVisible()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.data != null || intent.clipData != null ||
            intent.extras?.keySet() != setOf("token", "controllerId") ||
            intent.flags and (android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0) {
            finish(); return
        }
        if (android.os.Build.VERSION.SDK_INT >= 35) {
            // Caller identity is optional unless the launcher shared it. Never confuse
            // INVALID_UID with app UID or make API-29 security depend on this API.
            val caller = initialCaller.uid
            if (caller >= 0 && caller != 2000 && caller != android.os.Process.myUid()) { finish(); return }
        }
        title = applicationInfo.loadLabel(packageManager)
        setContentView(android.widget.ProgressBar(this).apply { isIndeterminate = true })
        // Lifecycle callbacks run under our UID, not the launcher's Binder UID.
        // DUMP + unpredictable owner-bound token is the API-29+ security boundary.
        val candidate = intent.getStringExtra("token")?.takeIf { runCatching { AndroidControlAccess.opaqueId(it) }.isSuccess }
        val epoch = intent.getStringExtra("controllerId")
        token = candidate
        session = if (candidate != null && epoch != null)
            owner.interactions.attach(candidate, epoch, savedInstanceState?.getString("session")) else null
        if (session == null) { finish(); return }
        permissionReturned = savedInstanceState?.getBoolean("permissionReturned") == true
        lifecycleScope.launch {
            owner.interactions.generation.collect {
                if (!owner.interactions.isActive(requireNotNull(token))) finish()
            }
        }
    }

    override fun onPostResume() { super.onPostResume(); continueWhenVisible() }
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) continueWhenVisible()
    }
    private fun continueWhenVisible() {
        val id = token ?: return
        val attached = session ?: return
        val visibleUnlocked = lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED) &&
            hasWindowFocus() && !getSystemService(KeyguardManager::class.java).isDeviceLocked && owner.foreground.ready()
        val action = owner.interactions.action(id, attached) ?: return
        if (action == com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_INSTALL) {
            when (androidInstallStage(visibleUnlocked, packageManager.canRequestPackageInstalls(), permissionReturned)) {
                AndroidInstallStage.WAIT -> return
                AndroidInstallStage.DENIED -> resolve(ControlCode.PERMISSION_DENIED)
                AndroidInstallStage.REQUEST_PERMISSION -> if (owner.interactions.claimConsent(id, attached)) runCatching {
                    installPermission.launch(android.content.Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        android.net.Uri.parse("package:$packageName")))
                }.onFailure { resolve(ControlCode.PERMISSION_DENIED) }
                AndroidInstallStage.DISPATCH -> if (!installDispatching) {
                    installDispatching = true
                    lifecycleScope.launch {
                        try {
                            owner.updateInstall.dispatch(id, attached) { intent ->
                                check(lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED) && hasWindowFocus() &&
                                    !getSystemService(KeyguardManager::class.java).isDeviceLocked && owner.foreground.ready())
                                check(packageManager.canRequestPackageInstalls())
                                startActivity(intent)
                            }
                        } finally { installDispatching = false }
                    }
                }
            }
            return
        }
        if (!visibleUnlocked) return
        val required = try { VpnService.prepare(this) } catch (_: Exception) { resolve(ControlCode.PERMISSION_DENIED); return }
        // Proxy-only requests need foreground eligibility, not VPN permission.
        if (!owner.connectionControl.requiresVpnConsent(id) || required == null) resolve(ControlCode.OK)
        else if (!permissionReturned && owner.interactions.claimConsent(id, attached)) {
            runCatching { consent.launch(required) }.onFailure { resolve(ControlCode.PERMISSION_DENIED) }
        }
        else if (permissionReturned) resolve(ControlCode.PERMISSION_DENIED)
    }
    private fun resolve(code: ControlCode) {
        val id = token ?: return
        val attached = session ?: return
        owner.interactions.resolve(id, attached, code)
    }
    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("session", session)
        outState.putBoolean("permissionReturned", permissionReturned)
        super.onSaveInstanceState(outState)
    }
    override fun onDestroy() {
        if (isFinishing && !isChangingConfigurations) resolve(ControlCode.PERMISSION_DENIED)
        super.onDestroy()
    }
}
