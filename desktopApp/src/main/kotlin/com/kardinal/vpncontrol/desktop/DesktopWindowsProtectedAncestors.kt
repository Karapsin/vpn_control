package com.kardinal.vpncontrol.desktop

/** Read-only ordinary-owner proof, retained until the privileged helper has admitted its own pins. */
internal object DesktopWindowsProtectedAncestors {
    fun retain(native: WindowsAdmissionNative): AutoCloseable {
        val handles = mutableListOf<WindowsInstallNative.Handle>()
        fun release() {
            var failure: Throwable? = null
            for (index in handles.indices.reversed()) {
                try { native.close(handles[index]); handles.removeAt(index) }
                catch (error: Throwable) { failure = failure ?: error }
            }
            failure?.let { throw it }
        }
        val lease = object : AutoCloseable {
            @Synchronized override fun close() = release()
        }
        fun witness(path: String, parent: WindowsInstallNative.Handle, canonicalParent: String) {
            for (name in native.children(path)) {
                if (name.isBlank() || name == "." || name == ".." || name.any { it in "\\/:\u0000" }) continue
                val child = try { native.openDirectory(path.trimEnd('\\') + "\\" + name) }
                catch (_: WindowsInstallNativeFailure) { continue }
                // Even a rejected witness remains owned if closing its native handle fails.
                handles += child
                var retained = false
                try {
                    val info = native.inspect(child)
                    require(info.disk && info.attributes and 0x400 == 0 && info.reparseTag == 0)
                    require(native.canonicalPath(child).substringBeforeLast('\\') == canonicalParent.trimEnd('\\'))
                    require(native.canonicalPath(parent) == canonicalParent)
                    WindowsInstallTrust.verify(native.inspect(parent), WindowsInstallTrust.Kind.ANCESTOR,
                        ancestorPinnedNonEmpty = true)
                    // openDirectory denies DELETE sharing for both directories and file witnesses.
                    // The linked retained child prevents this ancestor from becoming empty.
                    retained = true
                    return
                } catch (_: IllegalArgumentException) {
                    // A raced or unlinked entry proves nothing; another retained child may qualify.
                } finally {
                    if (!retained) {
                        native.close(child)
                        handles.remove(child)
                    }
                }
            }
            throw IllegalArgumentException("Unpinned mutable ancestor")
        }
        fun pin(path: String) {
            val handle = native.openDirectory(path)
            handles += handle
            require(native.persistentAcl(handle))
            val canonical = native.canonicalPath(handle)
            require(canonical.trimEnd('\\').equals(("\\\\?\\" + path).trimEnd('\\'), ignoreCase = true))
            val info = native.inspect(handle)
            try { WindowsInstallTrust.verify(info, WindowsInstallTrust.Kind.ANCESTOR) }
            catch (rejection: IllegalArgumentException) {
                // No rights other than the established ancestor attribute/EA exception may change.
                WindowsInstallTrust.verify(info, WindowsInstallTrust.Kind.ANCESTOR, ancestorPinnedNonEmpty = true)
                witness(path, handle, canonical)
            }
        }
        try {
            val root = DesktopWindowsInstallJobBackend.canonical(native.programData())
            var path = root.substring(0, 3)
            pin(path)
            if (root.length > 3) for (component in root.substring(3).split('\\')) {
                path = path.trimEnd('\\') + "\\" + component
                pin(path)
            }
            return lease
        } catch (failure: Throwable) {
            try { lease.close() }
            catch (_: Throwable) { throw DesktopWindowsAdmissionCleanupFailure(failure, lease) }
            throw failure
        }
    }
}

internal class DesktopWindowsAdmissionCleanupFailure(
    val originalFailure: Throwable,
    val retained: AutoCloseable,
) : java.io.IOException("UNAVAILABLE")
