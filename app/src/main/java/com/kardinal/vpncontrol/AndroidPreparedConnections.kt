package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import com.kardinal.vpncontrol.data.AndroidPersistedDomainSuffixes
import com.kardinal.vpncontrol.data.AndroidDirectDomainRuleSetStore
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.PersistedState
import java.lang.ref.WeakReference
import java.security.MessageDigest
import java.util.UUID

internal class AndroidPreparedRuntime(
    val configuration: ControlRuntimeConfiguration,
    private var asset: AndroidDirectDomainRuleSetStore.Lease?,
) : AutoCloseable {
    @Synchronized fun takeRuleSetLease(): AndroidDirectDomainRuleSetStore.Lease? = asset.also { asset = null }
    @Synchronized override fun close() { asset?.close(); asset = null }
}

/** Private preparation-to-start handoff. A matching file digest alone never authorizes a descriptor. */
internal class AndroidPreparedConnections(
    private val clockMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val capacity: Int = 128,
    private val retentionMillis: Long = 300_000,
) {
    private data class Prepared(
        val selection: WeakReference<ProfileSelection>, val digest: ByteArray,
        val configuration: ControlRuntimeConfiguration, val expiresAt: Long,
        val ruleSetLease: AndroidDirectDomainRuleSetStore.Lease?,
    ) {
        override fun toString(): String = "Prepared(<redacted>)"
    }
    private val preparations = mutableListOf<Prepared>()
    private val dispatched = linkedMapOf<String, Prepared>()

    fun remember(selection: ProfileSelection, state: PersistedState, ruleSetLease: AndroidDirectDomainRuleSetStore.Lease? = null) {
        // Generated SSH configurations use the exact captured credential version,
        // just like other runtime inputs. Uncaptured legacy JSON remains unknown.
        if (selection.profile.rawLink.isBlank()) { ruleSetLease?.close(); return }
        remember(selection, ControlRuntimeConfiguration(selection.profile.rawLink, selection.sourceUrl,
            state.appMode, state.routingRules, state.dnsSettings, state.homeSshRouteSettings), ruleSetLease)
    }

    @Synchronized fun remember(selection: ProfileSelection, configuration: ControlRuntimeConfiguration,
        ruleSetLease: AndroidDirectDomainRuleSetStore.Lease? = null) {
        try {
        prune()
        preparations.removeAll { if (it.selection.get() === selection) { it.ruleSetLease?.close(); true } else false }
        val captured = configuration.copy(
            routing = configuration.routing.copy(
                proxyPackages = configuration.routing.proxyPackages.toList(),
                bypassPackages = configuration.routing.bypassPackages.toList(),
                directDomainSuffixes = configuration.routing.directDomainSuffixes.let { domains ->
                    if (domains is AndroidPersistedDomainSuffixes) domains else domains.toList()
                },
                ruleSets = configuration.routing.ruleSets.toList(),
            ),
            ssh = configuration.ssh.copy(hostKeys = configuration.ssh.hostKeys.toList()),
        )
        preparations += Prepared(WeakReference(selection), digest(selection.runtimeConfigJson), captured, clockMillis() + retentionMillis, ruleSetLease)
        while (preparations.size > capacity) preparations.removeAt(0).ruleSetLease?.close()
        } catch (failure: Throwable) { ruleSetLease?.close(); throw failure }
    }

    @Synchronized fun dispatch(selection: ProfileSelection): String? {
        prune()
        val prepared = preparations.firstOrNull { it.selection.get() === selection } ?: return null
        if (dispatched.size >= capacity) return null
        return UUID.randomUUID().toString().also { dispatched[it] = prepared.copy(ruleSetLease = prepared.ruleSetLease?.retain()) }
    }

    fun consume(id: String?, actualRuntimeConfig: String): ControlRuntimeConfiguration? =
        consumePrepared(id, actualRuntimeConfig)?.use { it.configuration }

    @Synchronized fun consumePrepared(id: String?, actualRuntimeConfig: String): AndroidPreparedRuntime? {
        prune()
        val prepared = dispatched.remove(id) ?: return null
        return try {
            if (MessageDigest.isEqual(prepared.digest, digest(actualRuntimeConfig)))
                AndroidPreparedRuntime(prepared.configuration, prepared.ruleSetLease)
            else { prepared.ruleSetLease?.close(); null }
        } catch (failure: Throwable) { prepared.ruleSetLease?.close(); throw failure }
    }

    @Synchronized fun discard(id: String?) { dispatched.remove(id)?.ruleSetLease?.close() }

    private fun digest(config: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(config.toByteArray(Charsets.UTF_8))
    private fun prune() {
        val now = clockMillis()
        preparations.removeAll { if (it.expiresAt <= now || it.selection.get() == null) { it.ruleSetLease?.close(); true } else false }
        dispatched.entries.removeAll { if (it.value.expiresAt <= now) { it.value.ruleSetLease?.close(); true } else false }
    }
}
