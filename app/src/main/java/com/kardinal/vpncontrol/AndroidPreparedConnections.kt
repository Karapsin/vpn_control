package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import com.kardinal.vpncontrol.model.ProfileSelection
import java.lang.ref.WeakReference
import java.security.MessageDigest
import java.util.UUID

/** Private preparation-to-start handoff. A matching file digest alone never authorizes a descriptor. */
internal class AndroidPreparedConnections(
    private val clockMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val capacity: Int = 128,
    private val retentionMillis: Long = 300_000,
) {
    private data class Prepared(
        val selection: WeakReference<ProfileSelection>, val digest: ByteArray,
        val configuration: ControlRuntimeConfiguration, val expiresAt: Long,
    ) {
        override fun toString(): String = "Prepared(<redacted>)"
    }
    private val preparations = mutableListOf<Prepared>()
    private val dispatched = linkedMapOf<String, Prepared>()

    @Synchronized fun remember(selection: ProfileSelection, configuration: ControlRuntimeConfiguration) {
        prune()
        preparations.removeAll { it.selection.get() === selection }
        val captured = configuration.copy(
            routing = configuration.routing.copy(
                proxyPackages = configuration.routing.proxyPackages.toList(),
                bypassPackages = configuration.routing.bypassPackages.toList(),
                directDomainSuffixes = configuration.routing.directDomainSuffixes.toList(),
                ruleSets = configuration.routing.ruleSets.toList(),
            ),
            ssh = configuration.ssh.copy(hostKeys = configuration.ssh.hostKeys.toList()),
        )
        preparations += Prepared(WeakReference(selection), digest(selection.runtimeConfigJson), captured, clockMillis() + retentionMillis)
        while (preparations.size > capacity) preparations.removeAt(0)
    }

    @Synchronized fun dispatch(selection: ProfileSelection): String? {
        prune()
        val prepared = preparations.firstOrNull { it.selection.get() === selection } ?: return null
        if (dispatched.size >= capacity) return null
        return UUID.randomUUID().toString().also { dispatched[it] = prepared }
    }

    @Synchronized fun consume(id: String?, actualRuntimeConfig: String): ControlRuntimeConfiguration? {
        prune()
        val prepared = dispatched.remove(id) ?: return null
        return prepared.configuration.takeIf { MessageDigest.isEqual(prepared.digest, digest(actualRuntimeConfig)) }
    }

    @Synchronized fun discard(id: String?) { dispatched.remove(id) }

    private fun digest(config: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(config.toByteArray(Charsets.UTF_8))
    private fun prune() {
        val now = clockMillis()
        preparations.removeAll { it.expiresAt <= now || it.selection.get() == null }
        dispatched.entries.removeAll { it.value.expiresAt <= now }
    }
}
