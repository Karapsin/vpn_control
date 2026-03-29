package com.kardinal.vpncontrol.data

import android.content.Context
import com.kardinal.vpncontrol.model.VlessProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Connection
import okhttp3.Dns
import okhttp3.EventListener
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InterruptedIOException
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.zip.InflaterInputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import okhttp3.internal.http2.StreamResetException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.URI

data class AmneziaGatewayImport(
    val name: String,
    val serviceType: String,
    val userCountryCode: String,
    val authData: JSONObject,
)

object AmneziaGatewayResolver {
    private const val PREFS_NAME = "amnezia_gateway"
    private const val INSTALLATION_UUID_KEY = "installation_uuid"
    private const val GATEWAY_ENDPOINT = "http://gw.amnezia.org:80/"
    private const val CONFIG_ENDPOINT = "v1/config"
    private const val ACCOUNT_INFO_ENDPOINT = "v1/account_info"
    private const val AMNEZIA_APP_VERSION = "4.8.14.5"
    private const val CALL_TIMEOUT_SECONDS = 12L
    private const val CONNECT_TIMEOUT_SECONDS = 8L
    private const val READ_TIMEOUT_SECONDS = 12L
    private const val WRITE_TIMEOUT_SECONDS = 12L
    private const val ACCOUNT_INFO_MAX_ATTEMPTS = 2
    private const val ACCOUNT_INFO_RETRY_DELAY_MILLIS = 3_000L
    private const val TARGET_PROTOCOL = "vless"
    private const val PROXY_HEALTH_PATH = "lmbd-health"
    private const val PROXY_HEALTH_TIMEOUT_MILLIS = 1_000L
    private const val PROXY_STORAGE_TIMEOUT_SECONDS = 12L
    private const val ERROR_RESPONSE_PATTERN_1 = "No active configuration found for"
    private const val ERROR_RESPONSE_PATTERN_2 = "No non-revoked public key found for"
    private const val ERROR_RESPONSE_PATTERN_3 = "Account not found."
    private const val UPDATE_REQUIRED_PATTERN = "client version update is required"

    private val browserJson = "application/json; charset=utf-8".toMediaType()
    private val secureRandom = SecureRandom()
    private val proxyUrlCache = ConcurrentHashMap<String, String>()
    private val proxyStorageBaseUrls = listOf(
        "https://s3.eu-north-1.amazonaws.com/amnezia/",
        "https://storage.googleapis.com/lambda-list/",
        "https://amnzstrg01.blob.core.windows.net/lambda-list/",
        "https://objectstorage.eu-zurich-1.oraclecloud.com/n/zrhfyaq6qxvh/b/lambda-list/o/",
    )

    // Extracted from the official Amnezia Android client APK.
    private const val PROD_GATEWAY_PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj5mxl/4DL3Sk89ntxs5G
X3JawGQWIoq6rvNkOzNGuNgedNS2+pi6hZl3Izl1Io9om4KiUlMT6mgLO1hTr9q+
s7CYhlvroFA7ErucF+9L+7FCt0Igi0kIK/R2/vxd/2HaUrorn/aSvvutkYwbfxqW
SwtzE+RuBeDWGvEt937OW0oqYONPYv9E4T56Dz/EZ6v2t8ejAnKLbGD/GocMmipK
7etFSiSMAB2RmaztqTq4NleBepfO80XpYlW9pCSXuHcE8wxHczkzxsbyMAMsG/K3
vUQY6qPtohqqzSSBwa/8u2ptNHBeor7l7DdYXeR/Nqcc4z92VUkZ5lOVR4evkS5V
/wQqp5tnOJEj3NjUhEhXFoNEapbZd1bh6iQoUk7jC1TdvKJ/nPKGZAsHRpr0rNKz
fx/N/Oo6lr2yh/+ps6VxTkbPmB6E85WOO3UvjImZUY0XQdBjWle/4iJLdEC77Nr0
jXhdgeypucy6jkB6iBHMeVMlrNMEV7UxoBR/cCNx55zu/8sml5ByiDvCDT7sRomN
NgVt5S/FaVjYuzFUifJ12ToChXFgESKFmuso7WluEaWvMIGREdrMrKQKHfYLOzWF
2B5ZJDqw4o03fU4J/6rw61M1b+rjVpXMjPnzc2A+RgcjTvXv955gfZkwe4lt5wk/
3j8zMVo3+zLrMTAaEeIUM0UCAwEAAQ==
-----END PUBLIC KEY-----
"""

    private data class PreparedEncryptedRequest(
        val aesKey: ByteArray,
        val aesIv: ByteArray,
        val requestBody: String,
    )

    private class ProxyBypassException(
        message: String,
        cause: Throwable? = null,
    ) : IOException(message, cause)

    suspend fun resolveLocations(
        context: Context,
        source: AmneziaGatewayImport,
        onStatus: suspend (String) -> Unit = {},
    ): List<VlessProfile> = withContext(Dispatchers.IO) {
        val accountInfo = fetchAccountInfoWithRetry(
            context = context,
            source = source,
            onStatus = onStatus,
        )

        val supportedProtocols = jsonStringList(accountInfo.optJSONArray("supported_protocols"))
            .map { it.lowercase(Locale.ROOT) }
        if (supportedProtocols.isNotEmpty() && TARGET_PROTOCOL !in supportedProtocols) {
            error("This Amnezia import does not offer VLESS locations")
        }

        val countries = parseCountries(accountInfo.optJSONArray("available_countries"))
        val targets = if (countries.isNotEmpty()) {
            countries
        } else {
            listOf(AmneziaCountry("", source.name.ifBlank { "Default location" }))
        }
        DiagnosticsLogger.append(
            context,
            "Amnezia account info loaded: protocols=${
                supportedProtocols.ifEmpty { listOf("<unspecified>") }.joinToString(",")
            } countries=${targets.size}",
        )

        val installationUuid = installationUuid(context)
        val profiles = mutableListOf<VlessProfile>()
        val failures = mutableListOf<String>()
        for ((index, country) in targets.withIndex()) {
            val countryLabel = country.name.ifBlank { country.code.ifBlank { "default" } }
            onStatus("Loading Amnezia locations (${index + 1}/${targets.size}): $countryLabel...")
            val result = runCatching {
                val configResponse = postEncrypted(
                    context = context,
                    endpoint = CONFIG_ENDPOINT,
                    payload = JSONObject()
                        .put("os_version", "android")
                        .put("app_version", AMNEZIA_APP_VERSION)
                        .put("app_language", localeLanguage())
                        .put("installation_uuid", installationUuid)
                        .put("user_country_code", source.userCountryCode)
                        .put("server_country_code", country.code)
                        .put("service_type", source.serviceType)
                        .put("service_protocol", TARGET_PROTOCOL)
                        .put("auth_data", source.authData)
                        .put("public_key", UUID.randomUUID().toString()),
                    logLabel = "config[$countryLabel]",
                )
                parseGatewayVlessProfile(configResponse, source.name, country)
            }
            if (result.isSuccess) {
                profiles += result.getOrThrow()
            } else {
                val error = result.exceptionOrNull()
                failures += "$countryLabel: ${error?.message ?: "request failed"}"
                if (error?.message?.contains("rate limited", ignoreCase = true) == true) {
                    DiagnosticsLogger.append(
                        context,
                        "Amnezia config[$countryLabel] was rate limited; continuing with other locations",
                    )
                }
            }
        }

        if (profiles.isEmpty()) {
            runCatching {
                onStatus("Loading default Amnezia location...")
                val configResponse = postEncrypted(
                    context = context,
                    endpoint = CONFIG_ENDPOINT,
                    payload = JSONObject()
                        .put("os_version", "android")
                        .put("app_version", AMNEZIA_APP_VERSION)
                        .put("app_language", localeLanguage())
                        .put("installation_uuid", installationUuid)
                        .put("user_country_code", source.userCountryCode)
                        .put("server_country_code", "")
                        .put("service_type", source.serviceType)
                        .put("service_protocol", TARGET_PROTOCOL)
                        .put("auth_data", source.authData)
                        .put("public_key", UUID.randomUUID().toString()),
                    logLabel = "config[default]",
                )
                profiles += parseGatewayVlessProfile(
                    response = configResponse,
                    importName = source.name,
                    country = AmneziaCountry("", source.name.ifBlank { "Default location" }),
                )
            }.onFailure { error ->
                failures += "default: ${error.message ?: "request failed"}"
            }
        }

        require(profiles.isNotEmpty()) {
            failures.firstOrNull() ?: "No VLESS locations were returned by the Amnezia import"
        }

        DiagnosticsLogger.append(
            context,
            "Amnezia location loading complete: profiles=${profiles.size}",
        )
        profiles.distinctBy { it.rawLink.ifBlank { "${it.server}:${it.serverPort}:${it.uuid}:${it.publicKey}:${it.shortId}" } }
    }

    private suspend fun fetchAccountInfoWithRetry(
        context: Context,
        source: AmneziaGatewayImport,
        onStatus: suspend (String) -> Unit,
    ): JSONObject {
        var lastError: IOException? = null
        repeat(ACCOUNT_INFO_MAX_ATTEMPTS) { index ->
            val attempt = index + 1
            onStatus("Loading Amnezia account info (${attempt}/${ACCOUNT_INFO_MAX_ATTEMPTS})...")
            val result = runCatching {
                postEncrypted(
                    context = context,
                    endpoint = ACCOUNT_INFO_ENDPOINT,
                    payload = JSONObject()
                        .put("user_country_code", source.userCountryCode)
                        .put("service_type", source.serviceType)
                        .put("auth_data", source.authData)
                        .put("cli_version", AMNEZIA_APP_VERSION)
                        .put("app_language", localeLanguage()),
                    logLabel = "account_info[$attempt/$ACCOUNT_INFO_MAX_ATTEMPTS]",
                    addressOrderOffset = index,
                )
            }
            if (result.isSuccess) {
                return result.getOrThrow()
            }

            val error = result.exceptionOrNull() as? IOException
                ?: IOException(result.exceptionOrNull()?.message ?: "Amnezia account info failed")
            lastError = error
            val retryable = attempt < ACCOUNT_INFO_MAX_ATTEMPTS && isRetryableAccountInfoError(error)
            DiagnosticsLogger.append(
                context,
                "Amnezia account info attempt $attempt/$ACCOUNT_INFO_MAX_ATTEMPTS failed: ${error.message ?: error::class.java.simpleName}" +
                    if (retryable) " (retrying in ${ACCOUNT_INFO_RETRY_DELAY_MILLIS}ms)" else "",
            )
            if (retryable) {
                delay(ACCOUNT_INFO_RETRY_DELAY_MILLIS)
            }
        }

        throw buildAccountInfoFailure(lastError)
    }

    private fun postEncrypted(
        context: Context,
        endpoint: String,
        payload: JSONObject,
        logLabel: String,
        addressOrderOffset: Int = 0,
    ): JSONObject {
        val startedAt = System.nanoTime()
        return try {
            val response = postEncryptedInternal(
                context = context,
                endpoint = endpoint,
                payload = payload,
                logLabel = logLabel,
                addressOrderOffset = addressOrderOffset,
            )
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel succeeded in ${formatElapsedMillis(startedAt)}",
            )
            response
        } catch (error: Throwable) {
            val wrapped = wrapGatewayError(error)
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel failed in ${formatElapsedMillis(startedAt)}: ${wrapped.message ?: wrapped::class.java.simpleName}",
            )
            throw wrapped
        }
    }

    private fun wrapGatewayError(error: Throwable): IOException {
        return when (error) {
            is SocketTimeoutException -> IOException("Amnezia gateway timed out", error)
            is InterruptedIOException -> IOException("Amnezia gateway timed out", error)
            is StreamResetException -> IOException("Amnezia gateway interrupted the request", error)
            is IOException -> error
            else -> IOException(error.message ?: "Amnezia gateway request failed", error)
        }
    }

    private fun isRetryableAccountInfoError(error: IOException): Boolean {
        val message = error.message.orEmpty().lowercase(Locale.ROOT)
        return message.contains("timed out") ||
            message.contains("interrupted") ||
            message.contains("http 429") ||
            message.contains("http 500") ||
            message.contains("http 502") ||
            message.contains("http 503") ||
            message.contains("http 504")
    }

    private fun buildAccountInfoFailure(lastError: IOException?): IOException {
        if (lastError == null) {
            return IOException("Could not load Amnezia account info")
        }
        val message = lastError.message.orEmpty().lowercase(Locale.ROOT)
        return if (message.contains("timed out") || message == "timeout") {
            IOException(
                "Amnezia account info timed out after $ACCOUNT_INFO_MAX_ATTEMPTS attempts",
                lastError,
            )
        } else {
            IOException(
                "Amnezia account info failed after $ACCOUNT_INFO_MAX_ATTEMPTS attempts: ${lastError.message ?: lastError::class.java.simpleName}",
                lastError,
            )
        }
    }

    private fun formatElapsedMillis(startedAt: Long): String {
        val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000.0
        return String.format(Locale.US, "%.1fms", elapsedMillis)
    }

    private fun postEncryptedInternal(
        context: Context,
        endpoint: String,
        payload: JSONObject,
        logLabel: String,
        addressOrderOffset: Int,
    ): JSONObject {
        val prepared = prepareEncryptedRequest(payload)
        val cacheKey = proxyCacheKey(payload)
        val cachedProxy = proxyUrlCache[cacheKey]?.takeIf { it.isNotBlank() }

        if (cachedProxy != null) {
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel trying cached proxy before direct gateway: $cachedProxy",
            )
            val cachedResult = runCatching {
                executeEncryptedJsonRequest(
                    context = context,
                    baseUrl = cachedProxy,
                    endpoint = endpoint,
                    prepared = prepared,
                    logLabel = "$logLabel proxy[cached-first]",
                    client = proxyGatewayClient(context, "$logLabel proxy[cached-first]"),
                )
            }
            val cachedValue = cachedResult.getOrNull()
            if (cachedValue != null) {
                return cachedValue
            }
            val cachedError = cachedResult.exceptionOrNull()
            if (cachedError is IOException && cachedError !is ProxyBypassException) {
                throw cachedError
            }
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel cached proxy preflight failed, refreshing proxy path: ${cachedError?.message ?: "request failed"}",
            )
            proxyUrlCache.remove(cacheKey, cachedProxy)
            return executeViaProxy(
                context = context,
                endpoint = endpoint,
                payload = payload,
                prepared = prepared,
                logLabel = logLabel,
                directError = ProxyBypassException(cachedError?.message ?: "cached proxy failed", cachedError),
            )
        }

        val directResult = runCatching {
            executeEncryptedJsonRequest(
                context = context,
                baseUrl = GATEWAY_ENDPOINT,
                endpoint = endpoint,
                prepared = prepared,
                logLabel = logLabel,
                client = gatewayClient(context, logLabel, addressOrderOffset),
            )
        }
        val directValue = directResult.getOrNull()
        if (directValue != null) return directValue
        val directError = directResult.exceptionOrNull()
            ?: IOException("Amnezia gateway request failed")
        if (directError !is ProxyBypassException) {
            throw directError
        }

        DiagnosticsLogger.append(
            context,
            "Amnezia $logLabel switching to proxy endpoints: ${directError.message ?: directError::class.java.simpleName}",
        )
        return executeViaProxy(
            context = context,
            endpoint = endpoint,
            payload = payload,
            prepared = prepared,
            logLabel = logLabel,
            directError = directError,
        )
    }

    private fun prepareEncryptedRequest(payload: JSONObject): PreparedEncryptedRequest {
        val aesKey = ByteArray(32).also(secureRandom::nextBytes)
        val aesIv = ByteArray(32).also(secureRandom::nextBytes)
        val aesSalt = ByteArray(8).also(secureRandom::nextBytes)

        val keyPayload = JSONObject()
            .put("aes_key", Base64.getEncoder().encodeToString(aesKey))
            .put("aes_iv", Base64.getEncoder().encodeToString(aesIv))
            .put("aes_salt", Base64.getEncoder().encodeToString(aesSalt))
            .toString()
            .toByteArray()

        val requestBody = JSONObject()
            .put("key_payload", Base64.getEncoder().encodeToString(rsaEncrypt(keyPayload)))
            .put("api_payload", Base64.getEncoder().encodeToString(aesEncrypt(payload.toString().toByteArray(), aesKey, aesIv)))
            .toString()

        return PreparedEncryptedRequest(
            aesKey = aesKey,
            aesIv = aesIv,
            requestBody = requestBody,
        )
    }

    private fun executeViaProxy(
        context: Context,
        endpoint: String,
        payload: JSONObject,
        prepared: PreparedEncryptedRequest,
        logLabel: String,
        directError: ProxyBypassException,
    ): JSONObject {
        val cacheKey = proxyCacheKey(payload)
        val cachedProxy = proxyUrlCache[cacheKey]?.takeIf { it.isNotBlank() }
        var lastRetryable: ProxyBypassException = directError

        if (cachedProxy != null) {
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel trying cached proxy endpoint: $cachedProxy",
            )
            runCatching {
                executeEncryptedJsonRequest(
                    context = context,
                    baseUrl = cachedProxy,
                    endpoint = endpoint,
                    prepared = prepared,
                    logLabel = "$logLabel proxy[cached]",
                    client = proxyGatewayClient(context, "$logLabel proxy[cached]"),
                )
            }.onSuccess { return it }
                .onFailure { error ->
                    val ioError = error as? IOException ?: IOException(error.message ?: "Amnezia proxy request failed", error)
                    DiagnosticsLogger.append(
                        context,
                        "Amnezia $logLabel cached proxy failed: ${ioError.message ?: ioError::class.java.simpleName}",
                    )
                    if (ioError !is ProxyBypassException) {
                        throw ioError
                    }
                    lastRetryable = ioError
                }
        }

        val proxyUrls = loadProxyUrls(context, payload, logLabel)
        if (proxyUrls.isEmpty()) {
            throw IOException(
                "Amnezia proxy endpoint list is empty after direct gateway failure: ${lastRetryable.message ?: "no proxy endpoint responded"}",
                lastRetryable,
            )
        }

        val healthyProxy = proxyUrls.firstOrNull { probeProxyHealth(context, it, logLabel) }
        val orderedProxyUrls = buildList {
            healthyProxy?.let(::add)
            for (proxyUrl in proxyUrls) {
                if (proxyUrl != healthyProxy) add(proxyUrl)
            }
        }

        for (proxyUrl in orderedProxyUrls) {
            if (proxyUrl == cachedProxy) continue
            val proxyLogLabel = "$logLabel proxy[${hostLabel(proxyUrl).ifBlank { "remote" }}]"
            val result = runCatching {
                executeEncryptedJsonRequest(
                    context = context,
                    baseUrl = proxyUrl,
                    endpoint = endpoint,
                    prepared = prepared,
                    logLabel = proxyLogLabel,
                    client = proxyGatewayClient(context, proxyLogLabel),
                )
            }
            if (result.isSuccess) {
                proxyUrlCache[cacheKey] = proxyUrl
                return result.getOrThrow()
            }

            val error = result.exceptionOrNull() as? IOException
                ?: IOException(result.exceptionOrNull()?.message ?: "Amnezia proxy request failed", result.exceptionOrNull())
            DiagnosticsLogger.append(
                context,
                "Amnezia $proxyLogLabel failed: ${error.message ?: error::class.java.simpleName}",
            )
            if (error !is ProxyBypassException) {
                throw error
            }
            lastRetryable = error
        }

        throw IOException(
            "All Amnezia proxy endpoints failed: ${lastRetryable.message ?: "no proxy endpoint responded"}",
            lastRetryable,
        )
    }

    private fun executeEncryptedJsonRequest(
        context: Context,
        baseUrl: String,
        endpoint: String,
        prepared: PreparedEncryptedRequest,
        logLabel: String,
        client: OkHttpClient,
    ): JSONObject {
        val request = Request.Builder()
            .url(joinBaseUrl(baseUrl, endpoint))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Accept-Language", localeLanguage())
            .header("Connection", "close")
            .header("User-Agent", "Amnezia/$AMNEZIA_APP_VERSION (Android)")
            .header("X-Client-Request-ID", UUID.randomUUID().toString())
            .post(prepared.requestBody.toRequestBody(browserJson))
            .build()

        val response = try {
            client.newCall(request).execute()
        } catch (error: Throwable) {
            throw toRetryableProxyError(error)
        }

        response.use {
            if (!response.isSuccessful) {
                throw mapGatewayHttpError(response.code)
            }
            val encryptedBody = response.body?.bytes() ?: ByteArray(0)
            if (encryptedBody.isEmpty()) {
                throw ProxyBypassException("Amnezia gateway returned an empty response")
            }
            val decrypted = try {
                aesDecrypt(encryptedBody, prepared.aesKey, prepared.aesIv)
            } catch (error: Throwable) {
                throw ProxyBypassException("Amnezia gateway response could not be decrypted", error)
            }
            val decryptedText = decrypted.decodeToString()
            if (decryptedText.contains("html", ignoreCase = true)) {
                throw ProxyBypassException("Amnezia gateway returned HTML instead of JSON")
            }

            val responseJson = try {
                JSONObject(decryptedText)
            } catch (error: JSONException) {
                throw ProxyBypassException("Amnezia gateway returned unreadable JSON", error)
            }
            inspectDecryptedResponseBody(responseJson, decryptedText)
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel response ok from ${hostLabel(baseUrl).ifBlank { baseUrl }}",
            )
            return responseJson
        }
    }

    private fun inspectDecryptedResponseBody(responseJson: JSONObject, decryptedText: String) {
        when (responseJson.optInt("http_status", -1)) {
            404 -> {
                val message = decryptedText.lowercase(Locale.ROOT)
                if (
                    ERROR_RESPONSE_PATTERN_1.lowercase(Locale.ROOT) in message ||
                    ERROR_RESPONSE_PATTERN_2.lowercase(Locale.ROOT) in message ||
                    ERROR_RESPONSE_PATTERN_3.lowercase(Locale.ROOT) in message
                ) {
                    throw IOException("Amnezia gateway could not find an active configuration")
                }
                throw ProxyBypassException("Amnezia gateway returned an unexpected 404 response")
            }
            409 -> throw IOException("Amnezia gateway refused to issue a new config")
            422 -> throw IOException("This Amnezia import has expired")
            429 -> throw ProxyBypassException("Amnezia gateway rate limited the request")
            501 -> {
                if (decryptedText.contains(UPDATE_REQUIRED_PATTERN, ignoreCase = true)) {
                    throw IOException("Amnezia client version update is required")
                }
                throw ProxyBypassException("Amnezia gateway returned an unexpected 501 response")
            }
        }
    }

    private fun mapGatewayHttpError(statusCode: Int): IOException {
        return when (statusCode) {
            401, 403 -> IOException("Amnezia gateway rejected the import: HTTP $statusCode")
            404 -> IOException("Amnezia gateway endpoint was not found: HTTP 404")
            409 -> IOException("Amnezia gateway refused to issue a new config: HTTP 409")
            422 -> IOException("This Amnezia import has expired: HTTP 422")
            429 -> ProxyBypassException("Amnezia gateway rate limited the request: HTTP 429")
            500, 501, 502, 503, 504 -> ProxyBypassException("Amnezia gateway returned HTTP $statusCode")
            else -> ProxyBypassException("Amnezia gateway request failed: HTTP $statusCode")
        }
    }

    private fun toRetryableProxyError(error: Throwable): ProxyBypassException {
        val message = when (error) {
            is SocketTimeoutException -> "Amnezia gateway timed out"
            is InterruptedIOException -> "Amnezia gateway timed out"
            is StreamResetException -> "Amnezia gateway interrupted the request"
            is IOException -> error.message ?: "Amnezia gateway request failed"
            else -> error.message ?: "Amnezia gateway request failed"
        }
        return ProxyBypassException(message, error)
    }

    private fun proxyCacheKey(payload: JSONObject): String {
        val serviceType = payload.optString("service_type").trim()
        val country = payload.optString("user_country_code").trim().lowercase(Locale.ROOT)
        return "$serviceType|$country"
    }

    private fun loadProxyUrls(
        context: Context,
        payload: JSONObject,
        logLabel: String,
    ): List<String> {
        val serviceType = payload.optString("service_type").trim()
        val userCountryCode = payload.optString("user_country_code").trim().lowercase(Locale.ROOT)
        val storageUrls = buildProxyStorageUrls(serviceType, userCountryCode)
        val client = proxyStorageClient()

        for (storageUrl in storageUrls) {
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel loading proxy storage: $storageUrl",
            )
            val request = Request.Builder()
                .url(storageUrl)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", "Amnezia/$AMNEZIA_APP_VERSION (Android)")
                .get()
                .build()
            val endpoints = runCatching {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        throw IOException("HTTP ${response.code}")
                    }
                    val encryptedBody = response.body?.string().orEmpty().trim()
                    if (encryptedBody.isBlank()) {
                        throw IOException("empty response")
                    }
                    val manifest = if (encryptedBody.startsWith("[") || encryptedBody.startsWith("{")) {
                        encryptedBody
                    } else {
                        decryptProxyManifest(encryptedBody)
                    }
                    parseProxyManifest(manifest)
                }
            }.getOrElse { error ->
                DiagnosticsLogger.append(
                    context,
                    "Amnezia $logLabel proxy storage failed: ${error.message ?: error::class.java.simpleName}",
                )
                emptyList()
            }
            if (endpoints.isNotEmpty()) {
                DiagnosticsLogger.append(
                    context,
                    "Amnezia $logLabel proxy storage returned ${endpoints.size} endpoints",
                )
                return endpoints.shuffled()
            }
        }

        return emptyList()
    }

    private fun buildProxyStorageUrls(serviceType: String, userCountryCode: String): List<String> {
        val randomizedBaseUrls = proxyStorageBaseUrls.shuffled()
        return buildList {
            if (serviceType.isNotBlank()) {
                val encodedPath = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString("endpoints-$serviceType-$userCountryCode".toByteArray())
                randomizedBaseUrls.forEach { baseUrl ->
                    add(baseUrl + encodedPath + ".json")
                }
            }
            randomizedBaseUrls.forEach { baseUrl ->
                add(baseUrl + "endpoints.json")
            }
        }
    }

    private fun decryptProxyManifest(encryptedBody: String): String {
        val digest = MessageDigest.getInstance("SHA-512")
            .digest(normalizedGatewayPem().toByteArray())
        val key = digest.copyOfRange(0, 32)
        val iv = digest.copyOfRange(32, 48)
        val decoded = Base64.getMimeDecoder().decode(encryptedBody)
        return aesDecrypt(decoded, key, iv).decodeToString()
    }

    private fun parseProxyManifest(raw: String): List<String> {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return emptyList()
        val directArray = runCatching { JSONArray(trimmed) }.getOrNull()
        if (directArray != null) {
            return jsonStringList(directArray)
                .map(::normalizeProxyBaseUrl)
                .filter { it.isNotBlank() }
                .distinct()
        }

        val jsonObject = runCatching { JSONObject(trimmed) }.getOrNull() ?: return emptyList()
        val candidateArrays = listOf(
            jsonObject.optJSONArray("endpoints"),
            jsonObject.optJSONArray("proxy_urls"),
            jsonObject.optJSONArray("urls"),
        )
        for (candidateArray in candidateArrays) {
            val urls = jsonStringList(candidateArray)
                .map(::normalizeProxyBaseUrl)
                .filter { it.isNotBlank() }
                .distinct()
            if (urls.isNotEmpty()) {
                return urls
            }
        }
        return emptyList()
    }

    private fun probeProxyHealth(
        context: Context,
        proxyBaseUrl: String,
        logLabel: String,
    ): Boolean {
        val request = Request.Builder()
            .url(joinBaseUrl(proxyBaseUrl, PROXY_HEALTH_PATH))
            .header("User-Agent", "Amnezia/$AMNEZIA_APP_VERSION (Android)")
            .get()
            .build()
        val startedAt = System.nanoTime()
        return runCatching {
            proxyHealthClient(context, "$logLabel health").newCall(request).execute().use { response ->
                response.isSuccessful
            }
        }.onSuccess { healthy ->
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel health ${hostLabel(proxyBaseUrl).ifBlank { proxyBaseUrl }}=${if (healthy) "ok" else "bad"} in ${formatElapsedMillis(startedAt)}",
            )
        }.onFailure { error ->
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel health ${hostLabel(proxyBaseUrl).ifBlank { proxyBaseUrl }} failed in ${formatElapsedMillis(startedAt)}: ${error.message ?: error::class.java.simpleName}",
            )
        }.getOrDefault(false)
    }

    private fun normalizeProxyBaseUrl(url: String): String {
        val trimmed = url.trim()
        if (trimmed.isBlank()) return ""
        return if (trimmed.endsWith("/")) trimmed else "$trimmed/"
    }

    private fun joinBaseUrl(baseUrl: String, endpoint: String): String {
        val normalizedBaseUrl = normalizeProxyBaseUrl(baseUrl)
        val normalizedEndpoint = endpoint.removePrefix("/")
        return normalizedBaseUrl + normalizedEndpoint
    }

    private fun gatewayClient(context: Context, logLabel: String, addressOrderOffset: Int): OkHttpClient {
        return OkHttpClient.Builder()
            .callTimeout(CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .dns(GatewayDns(context, logLabel, addressOrderOffset))
            .eventListenerFactory { GatewayEventLogger(context, logLabel) }
            .build()
    }

    private fun proxyGatewayClient(context: Context, logLabel: String): OkHttpClient {
        return OkHttpClient.Builder()
            .callTimeout(CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .eventListenerFactory { GatewayEventLogger(context, logLabel) }
            .build()
    }

    private fun proxyStorageClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .callTimeout(PROXY_STORAGE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(PROXY_STORAGE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }

    private fun proxyHealthClient(context: Context, logLabel: String): OkHttpClient {
        return OkHttpClient.Builder()
            .callTimeout(PROXY_HEALTH_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            .connectTimeout(PROXY_HEALTH_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            .readTimeout(PROXY_HEALTH_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            .writeTimeout(PROXY_HEALTH_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            .retryOnConnectionFailure(false)
            .eventListenerFactory { GatewayEventLogger(context, logLabel) }
            .build()
    }

    private class GatewayDns(
        private val context: Context,
        private val logLabel: String,
        private val addressOrderOffset: Int,
    ) : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val resolved = Dns.SYSTEM.lookup(hostname)
            val sorted = resolved.sortedWith(
                compareBy<InetAddress>(
                    { if (it is Inet4Address) 0 else 1 },
                    { it.hostAddress ?: "" },
                ),
            )
            val ordered = if (sorted.size > 1) {
                val normalizedOffset = ((addressOrderOffset % sorted.size) + sorted.size) % sorted.size
                if (normalizedOffset == 0) {
                    sorted
                } else {
                    buildList(sorted.size) {
                        for (index in sorted.indices) {
                            add(sorted[(index + normalizedOffset) % sorted.size])
                        }
                    }
                }
            } else {
                sorted
            }
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel DNS[$addressOrderOffset] $hostname -> ${ordered.joinToString(",") { it.hostAddress ?: "<unknown>" }}",
            )
            return ordered
        }
    }

    private class GatewayEventLogger(
        private val context: Context,
        private val logLabel: String,
    ) : EventListener() {
        override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) {
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel connect start: ${inetSocketAddress.address?.hostAddress ?: inetSocketAddress.hostString}:${inetSocketAddress.port} via ${proxy.type()}",
            )
        }

        override fun connectEnd(
            call: Call,
            inetSocketAddress: InetSocketAddress,
            proxy: Proxy,
            protocol: okhttp3.Protocol?,
        ) {
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel connect end: ${inetSocketAddress.address?.hostAddress ?: inetSocketAddress.hostString}:${inetSocketAddress.port}",
            )
        }

        override fun connectFailed(
            call: Call,
            inetSocketAddress: InetSocketAddress,
            proxy: Proxy,
            protocol: okhttp3.Protocol?,
            ioe: IOException,
        ) {
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel connect failed: ${inetSocketAddress.address?.hostAddress ?: inetSocketAddress.hostString}:${inetSocketAddress.port} ${ioe.message ?: ioe::class.java.simpleName}",
            )
        }

        override fun connectionAcquired(call: Call, connection: Connection) {
            val route = connection.route()
            val socketAddress = route.socketAddress as? InetSocketAddress
            DiagnosticsLogger.append(
                context,
                "Amnezia $logLabel connection acquired: ${
                    socketAddress?.address?.hostAddress ?: socketAddress?.hostString ?: "<unknown>"
                }:${socketAddress?.port ?: -1}",
            )
        }
    }

    private fun parseGatewayVlessProfile(
        response: JSONObject,
        importName: String,
        country: AmneziaCountry,
    ): VlessProfile {
        val configToken = response.optString("config").trim()
        require(configToken.isNotBlank()) { "Amnezia gateway response did not include a config" }

        val wrapper = JSONObject(decodeConfigToken(configToken))
        val container = selectXrayContainer(wrapper)
        val xrayContainer = container.optJSONObject("xray")
            ?: error("Amnezia gateway returned a non-VLESS config")
        val lastConfig = xrayContainer.optString("last_config").trim()
        require(lastConfig.isNotBlank()) { "Amnezia gateway returned an empty Xray config" }
        val xrayConfig = JSONObject(lastConfig)

        val outbound = xrayConfig.optJSONArray("outbounds")
            ?.optJSONObject(0)
            ?: error("Amnezia gateway returned an incomplete Xray config")
        val vnext = outbound.optJSONObject("settings")
            ?.optJSONArray("vnext")
            ?.optJSONObject(0)
            ?: error("Amnezia gateway returned an incomplete VLESS config")
        val user = vnext.optJSONArray("users")
            ?.optJSONObject(0)
            ?: error("Amnezia gateway returned an incomplete VLESS user config")

        val stream = outbound.optJSONObject("streamSettings") ?: JSONObject()
        val security = stream.optString("security")
        val tlsKey = when (security) {
            "reality" -> "realitySettings"
            "tls" -> "tlsSettings"
            "xtls" -> "xtlsSettings"
            else -> ""
        }
        val tls = if (tlsKey.isNotBlank()) stream.optJSONObject(tlsKey) ?: JSONObject() else JSONObject()

        val network = stream.optString("network").ifBlank { "tcp" }
        val hostHeader = when (network) {
            "ws" -> stream.optJSONObject("wsSettings")
                ?.optJSONObject("headers")
                ?.optString("Host")
                .orEmpty()
            "http" -> stream.optJSONObject("httpSettings")
                ?.optJSONArray("host")
                ?.optString(0)
                .orEmpty()
            else -> ""
        }
        val path = when (network) {
            "ws" -> stream.optJSONObject("wsSettings")?.optString("path").orEmpty()
            "http" -> stream.optJSONObject("httpSettings")?.optString("path").orEmpty()
            else -> ""
        }
        val serviceName = if (network == "grpc") {
            stream.optJSONObject("grpcSettings")?.optString("serviceName").orEmpty()
        } else {
            ""
        }

        val remarks = country.name.ifBlank {
            wrapper.optString("description")
                .ifBlank { wrapper.optString("name") }
                .ifBlank { importName }
                .ifBlank { vnext.optString("address") }
        }

        val baseProfile = VlessProfile(
            remarks = remarks,
            uuid = user.optString("id"),
            server = vnext.optString("address").ifBlank { wrapper.optString("hostName") },
            serverPort = vnext.optInt("port", 443),
            network = network,
            flow = user.optString("flow"),
            security = security,
            sni = tls.optString("serverName").ifBlank {
                wrapper.optString("hostName").ifBlank { vnext.optString("address") }
            },
            fingerprint = tls.optString("fingerprint").ifBlank { "chrome" },
            publicKey = tls.optString("publicKey"),
            shortId = tls.optString("shortId"),
            path = path,
            hostHeader = hostHeader,
            serviceName = serviceName,
            headerType = "none",
            rawLink = "",
        )
        val rawLink = VlessParser.encodeVlessLink(baseProfile)
        return baseProfile.copy(rawLink = rawLink)
    }

    private fun selectXrayContainer(wrapper: JSONObject): JSONObject {
        val containers = wrapper.optJSONArray("containers") ?: error("Amnezia gateway config is missing containers")
        for (index in 0 until containers.length()) {
            val container = containers.optJSONObject(index) ?: continue
            if (container.has("xray") || container.optString("container") == "amnezia-xray") {
                return container
            }
        }
        error("Amnezia gateway did not return an Xray location")
    }

    private fun decodeConfigToken(raw: String): String {
        val encoded = raw.removePrefix("vpn://").trim()
        require(encoded.isNotBlank()) { "Amnezia gateway config is empty" }
        val payload = Base64.getUrlDecoder().decode(encoded.padBase64())

        val candidates = sequenceOf(
            payload.decodeJsonOrNull(),
            payload.qtUncompressOrNull()?.decodeJsonOrNull(),
            payload.inflateOrNull()?.decodeJsonOrNull(),
        ).filterNotNull()

        return candidates.firstOrNull()
            ?: error("Amnezia gateway config format is not recognized")
    }

    private fun ByteArray.decodeJsonOrNull(): String? {
        return runCatching {
            decodeToString().takeIf { it.trim().startsWith("{") }
        }.getOrNull()
    }

    private fun ByteArray.qtUncompressOrNull(): ByteArray? {
        if (size <= 4) return null
        return inflateBytes(copyOfRange(4, size))
    }

    private fun ByteArray.inflateOrNull(): ByteArray? = inflateBytes(this)

    private fun inflateBytes(bytes: ByteArray): ByteArray? {
        return runCatching {
            InflaterInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
        }.getOrNull()
    }

    private fun parseCountries(raw: JSONArray?): List<AmneziaCountry> {
        if (raw == null) return emptyList()
        return buildList {
            for (index in 0 until raw.length()) {
                val item = raw.optJSONObject(index) ?: continue
                val code = item.optString("server_country_code").trim()
                val name = item.optString("server_country_name").trim()
                if (code.isNotBlank() || name.isNotBlank()) {
                    add(
                        AmneziaCountry(
                            code = code,
                            name = name.ifBlank { code.uppercase(Locale.ROOT) },
                        ),
                    )
                }
            }
        }.distinctBy { it.code.ifBlank { it.name } }
    }

    private fun jsonStringList(raw: JSONArray?): List<String> {
        if (raw == null) return emptyList()
        return buildList {
            for (index in 0 until raw.length()) {
                raw.optString(index).trim().takeIf { it.isNotBlank() }?.let(::add)
            }
        }
    }

    private fun rsaEncrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, gatewayPublicKey())
        return cipher.doFinal(plain)
    }

    private fun aesEncrypt(plain: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv.copyOf(16)))
        return cipher.doFinal(plain)
    }

    private fun aesDecrypt(cipherText: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv.copyOf(16)))
        return cipher.doFinal(cipherText)
    }

    private fun gatewayPublicKey(): PublicKey {
        val pem = normalizedGatewayPem()
            .lineSequence()
            .filterNot { it.startsWith("-----") }
            .joinToString("")
        val decoded = Base64.getDecoder().decode(pem)
        val spec = X509EncodedKeySpec(decoded)
        return KeyFactory.getInstance("RSA").generatePublic(spec)
    }

    private fun normalizedGatewayPem(): String = PROD_GATEWAY_PUBLIC_KEY_PEM.trim()

    private fun hostLabel(url: String): String {
        return runCatching { URI(url).host }
            .getOrNull()
            ?.removePrefix("www.")
            ?.takeIf { it.isNotBlank() }
            .orEmpty()
    }

    private fun localeLanguage(): String = Locale.getDefault().language.ifBlank { "en" }

    private fun installationUuid(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val existing = prefs.getString(INSTALLATION_UUID_KEY, null)
        if (!existing.isNullOrBlank()) return existing
        val generated = UUID.randomUUID().toString()
        prefs.edit().putString(INSTALLATION_UUID_KEY, generated).apply()
        return generated
    }

    private fun String.padBase64(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }

    private data class AmneziaCountry(
        val code: String,
        val name: String,
    )
}
