package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlinx.serialization.json.*

/** Ordinary-owner preparation, before privileged IO. Never mutates the persisted runtime configuration. */
internal object DesktopWindowsVpnConfigCapture {
    private const val KEY_BYTE_LIMIT = 512 * 1024
    fun prepare(config: String, managedKey: Path? = null, readKey: (Path) -> String = ::readManagedKey): String =
        prepareDocument(config, managedKey, readKey)

    fun capture(config: String, baseDirectory: Path, managedKey: Path? = null,
                captureResource: (Path, Path) -> DesktopWindowsCapturedResource = { path, parent ->
                    DesktopWindowsCapturedResource.capture(path, parent)
                },
                admitMutableResource: (Path, DesktopWindowsRuntimeResourceKind) -> DesktopWindowsRuntimeResource =
                    { path, kind -> DesktopWindowsRuntimeResource.admit(path, kind) },
    ): DesktopWindowsCapturedConfiguration {
        val resources = mutableListOf<DesktopWindowsCapturedResource>()
        val mutable = mutableListOf<DesktopWindowsRuntimeResource>()
        try {
            val captured = prepareDocument(config, managedKey, ::readManagedKey, captureFile = { requested ->
                val path = Path.of(requested).let { if (it.isAbsolute) it else baseDirectory.resolve(it) }
                val resource = try { captureResource(path, baseDirectory) }
                catch (failure: Throwable) {
                    if (failure is DesktopWindowsRuntimeFailure) throw failure
                    // Filesystem admission and private-spool policy run after JSON validation.
                    // Their require/check failures do not make the user's document malformed.
                    val code = when (failure) {
                        is DesktopWindowsRuntimeFailure -> failure.code
                        is OutOfMemoryError -> "RESOURCE_EXHAUSTED"
                        is WindowsInstallNativeFailure -> when (failure.code) {
                            5 -> "PERMISSION_DENIED"
                            39, 112 -> "RESOURCE_EXHAUSTED"
                            else -> "UNAVAILABLE"
                        }
                        is java.nio.file.AccessDeniedException, is SecurityException, is IllegalArgumentException -> "PERMISSION_DENIED"
                        else -> if (failure.message == "CONFLICT") "CONFLICT" else "UNAVAILABLE"
                    }
                    throw DesktopWindowsRuntimeFailure(code, stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
                }
                resources += resource
                resource.reference
            }, captureMutable = { requested, kind ->
                val path = Path.of(requested).let { if (it.isAbsolute) it else baseDirectory.resolve(it) }
                val resource = try { admitMutableResource(path, kind) }
                catch (failure: Throwable) {
                    if (failure is DesktopWindowsRuntimeFailure) throw failure
                    val code = when (failure) {
                        is DesktopWindowsRuntimeFailure -> failure.code
                        is OutOfMemoryError -> "RESOURCE_EXHAUSTED"
                        is WindowsInstallNativeFailure -> when (failure.code) {
                            5 -> "PERMISSION_DENIED"
                            39, 112 -> "RESOURCE_EXHAUSTED"
                            else -> "UNAVAILABLE"
                        }
                        is java.nio.file.AccessDeniedException, is SecurityException -> "PERMISSION_DENIED"
                        else -> if (failure.message == "CONFLICT") "CONFLICT" else "UNAVAILABLE"
                    }
                    throw DesktopWindowsRuntimeFailure(code, stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
                }
                val destination = resource.destination
                val leaf = destination.path.replace('/', '\\').substringAfterLast('\\')
                check(mutable.none { previous ->
                    previous.destination.parentIdentity == destination.parentIdentity &&
                        previous.destination.path.replace('/', '\\').substringAfterLast('\\').equals(leaf, ignoreCase = true)
                }) { "CONFLICT" }
                mutable += resource
                resource.reference
            })
            return DesktopWindowsCapturedConfiguration(captured, resources.toList(), mutable.toList())
        } catch (failure: Throwable) {
            val nativeFailure = failure as? DesktopWindowsRuntimeFailure
            val pending = (resources + listOfNotNull(nativeFailure?.retainedAdmission))
                .distinct().toMutableList()
            val cleanup = object : AutoCloseable {
                @Synchronized override fun close() {
                    var rejected: Exception? = null
                    for (index in pending.indices.reversed()) {
                        try { pending[index].close(); pending.removeAt(index) }
                        catch (error: Exception) { rejected = rejected ?: error }
                    }
                    rejected?.let { throw it }
                }
            }
            // The transition owner can retry private-input disposal even when JSON validation
            // failed before returning a candidate. Never lose a failed spool behind a new error.
            val retained = if (runCatching { cleanup.close() }.isFailure) cleanup else null
            val code = when (failure) {
                is DesktopWindowsRuntimeFailure -> failure.code
                is OutOfMemoryError -> "RESOURCE_EXHAUSTED"
                is java.nio.file.AccessDeniedException -> "PERMISSION_DENIED"
                is IllegalArgumentException -> if (failure.message == "UNSUPPORTED") "UNSUPPORTED" else "INVALID_ARGUMENT"
                else -> if (failure.message == "CONFLICT") "CONFLICT" else "UNAVAILABLE"
            }
            throw DesktopWindowsRuntimeFailure(code, unresolvedRuntime = nativeFailure?.unresolvedRuntime,
                stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS, retainedAdmission = retained)
        }
    }

    private fun prepareDocument(config: String, managedKey: Path?, readKey: (Path) -> String,
                                captureFile: ((String) -> String)? = null,
                                captureMutable: ((String, DesktopWindowsRuntimeResourceKind) -> String)? = null): String {
        fun capture(value: JsonElement): JsonElement = when (value) {
            is JsonPrimitive -> {
                require(value.isString && value.content.isNotEmpty()) { "INVALID_ARGUMENT" }
                JsonPrimitive(requireNotNull(captureFile) { "UNSUPPORTED" }(value.content))
            }
            is JsonArray -> JsonArray(value.map { capture(it) })
            else -> throw IllegalArgumentException("INVALID_ARGUMENT")
        }
        fun transform(value: JsonElement, context: List<String>): JsonElement = when (value) {
            is JsonObject -> {
                val type = (value["type"] as? JsonPrimitive)?.contentOrNull
                val urlContext = (context == listOf("dns", "servers", "*") && type in setOf("https", "h3")) ||
                    (context in listOf(listOf("outbounds", "*", "transport"), listOf("inbounds", "*", "transport")) &&
                        type in setOf("ws", "http", "httpupgrade")) || (context == listOf("outbounds", "*") && type == "http")
                val cache = context == listOf("experimental", "cache_file")
                val log = context == listOf("log")
                val logDisabled = if (log) value["disabled"]?.let {
                    require(it is JsonPrimitive && !it.isString && it.booleanOrNull != null) { "INVALID_ARGUMENT" }
                    it.boolean
                } == true else false
                var cachePath = "cache.db"
                if (cache) {
                    require(value.keys.all { it in setOf("enabled", "path", "cache_id", "store_fakeip", "store_rdrc", "rdrc_timeout") }) { "UNSUPPORTED" }
                    require("enabled" !in value || (value["enabled"] as? JsonPrimitive)?.let { !it.isString && it.booleanOrNull != null } == true) { "INVALID_ARGUMENT" }
                    val requested = value["path"]?.let { path ->
                        require(path is JsonPrimitive && path.isString) { "INVALID_ARGUMENT" }
                        path.content.ifEmpty { "cache.db" }
                    } ?: "cache.db"
                    if (captureFile == null) require(value.keys == setOf("enabled")) { "UNSUPPORTED" }
                    else if (value["enabled"]?.jsonPrimitive?.booleanOrNull == true)
                        cachePath = requireNotNull(captureMutable) { "UNAVAILABLE" }(requested, DesktopWindowsRuntimeResourceKind.CACHE)
                }
                JsonObject(buildMap {
                    value.forEach { (key, child) ->
                        if (cache && key == "path") Unit // The admitted descriptor supplies the runtime path.
                        else if (log && key == "output") {
                            require(child is JsonPrimitive && child.isString) { "INVALID_ARGUMENT" }
                            val requested = child.content
                            val destination = when {
                                logDisabled -> ""
                                requested in setOf("", "stdout", "stderr") -> requested
                                else -> requireNotNull(captureMutable) { "UNSUPPORTED" }(
                                    requested, DesktopWindowsRuntimeResourceKind.OUTPUT)
                            }
                            put(key, JsonPrimitive(destination))
                        }
                        else if (key == "private_key_path" && context == listOf("outbounds", "*") && type == "ssh") {
                            val expected = managedKey
                            val requested = (child as? JsonPrimitive)?.takeIf { it.isString }?.content
                            if (requested != null && expected != null && Path.of(requested).toAbsolutePath().normalize() ==
                                expected.toAbsolutePath().normalize() && "private_key" !in value) {
                                val captured = readKey(expected)
                                require(captured.isNotBlank() && captured.length <= 128 * 1024 &&
                                    captured.encodeToByteArray().size <= KEY_BYTE_LIMIT) { "INVALID_ARGUMENT" }
                                put("private_key", JsonPrimitive(captured))
                            } else {
                                require("private_key" !in value) { "UNSUPPORTED" }
                                put(key, capture(child))
                            }
                        } else if (captureFile != null && isReadFile(key, context, type)) {
                            put(key, capture(child))
                        } else {
                            require(key !in setOf("output", "external_ui", "directory") && !key.endsWith("_directory") &&
                                (key == "cache_file" || !key.endsWith("_file")) &&
                                (key in setOf("process_path", "tcp_multi_path") || !key.endsWith("_path")) &&
                                (key != "cache_file" || context == listOf("experimental"))) { "UNSUPPORTED" }
                            if (key == "masquerade" && child is JsonPrimitive && child.isString)
                                require(!child.content.startsWith("file:", ignoreCase = true)) { "UNSUPPORTED" }
                            if (key == "path") {
                                val path = (child as? JsonPrimitive)?.takeIf { it.isString }?.content
                                require(urlContext && path != null) { "UNSUPPORTED" }
                            }
                            put(key, transform(child, context + key))
                        }
                    }
                    if (cache) put("path", JsonPrimitive(cachePath))
                })
            }
            is JsonArray -> JsonArray(value.map { transform(it, context + "*") })
            else -> value
        }
        return transform(Json.parseToJsonElement(config), emptyList()).toString()
    }

    private fun isReadFile(key: String, context: List<String>, type: String?): Boolean =
        (context.lastOrNull() == "tls" && key in setOf("certificate_path", "client_certificate_path", "key_path", "client_key_path")) ||
            (context.takeLast(2) == listOf("tls", "ech") && key in setOf("key_path", "config_path")) ||
            (context == listOf("certificate") && key == "certificate_path") ||
            (context == listOf("dns", "servers", "*") && type == "hosts" && key == "path") ||
            (context == listOf("route", "rule_set", "*") && type == "local" && key == "path") ||
            (context == listOf("services", "*") && type == "derp" && key == "mesh_psk_file")

    private fun readManagedKey(path: Path): String {
        // Runs under the original owner token. No privileged helper ever opens this workspace path.
        Files.newByteChannel(path, setOf(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)).use { source ->
            require(source.size() in 1..KEY_BYTE_LIMIT.toLong()) { "INVALID_ARGUMENT" }
            val buffer = ByteBuffer.allocate(KEY_BYTE_LIMIT + 1)
            while (buffer.hasRemaining() && source.read(buffer) != -1) { }
            require(buffer.position() in 1..KEY_BYTE_LIMIT) { "INVALID_ARGUMENT" }
            buffer.flip()
            return Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(buffer).toString()
        }
    }
}
