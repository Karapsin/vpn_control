package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidControlReaderTest {
    @Test fun diagnosticsExportUsesCapturedConfigurationAndRejectsClientPathBeforeExporter() = runTest {
        var calls = 0
        val reader = AndroidControlReader("owner", { error("Legacy snapshot must not be used") },
            committedSnapshot = { com.kardinal.vpncontrol.control.ControlCommitted("owner", 6,
                PersistedState(appMode = AppMode.PROXY_ONLY)) }, diagnosticsExport = { state ->
                calls++
                assertEquals(AppMode.PROXY_ONLY, state.appMode)
                "SANITIZED_REPORT"
            })
        val result = reader.read(request(ControlOperationId.DIAGNOSTICS_EXPORT))
        assertEquals(ControlCode.OK, result.code)
        assertEquals(6, result.configurationRevision)
        assertEquals(ControlValue.Text("SANITIZED_REPORT"), result.data["content"])
        assertEquals(1, calls)
        assertEquals(ControlCode.INVALID_ARGUMENT, reader.read(request(ControlOperationId.DIAGNOSTICS_EXPORT,
            mapOf("output" to ControlValue.Text("device-path")))).code)
        assertEquals(1, calls)
    }
    @Test fun locationReadsUseOneCommittedRevisionAndTheSameSystemLocalizedProjectionAsGui() = runTest {
        val raw = "socks://user:PROFILE_SECRET@127.0.0.1:1080#Fixture"
        var snapshots = 0
        val persisted = PersistedState(appLanguage = AppLanguage.SYSTEM, currentLocations = listOf(raw),
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS)
        val reader = AndroidControlReader("owner", { error("No second or legacy snapshot") },
            systemLanguageCode = { "ru" }, committedSnapshot = {
                snapshots++
                com.kardinal.vpncontrol.control.ControlCommitted("owner", 29, persisted)
            })
        suspend fun execute(operation: ControlOperationId, arguments: Map<String, ControlValue> = emptyMap()) =
            ControlProtocolCodec.decodeResult(reader.execute(ControlProtocolCodec.encodeRequest(request(operation, arguments))
                .toByteArray(), "transfer").toString(Charsets.UTF_8))
        val listed = execute(ControlOperationId.LOCATIONS_LIST)
        val name = com.kardinal.vpncontrol.shared.ui.AppStrings(AppLanguage.RUSSIAN)
            .locationLabel(persisted.profileSourceMode, "Fixture")
        val row = ((listed.data.getValue("locations") as ControlValue.ArrayValue).values.single() as ControlValue.ObjectValue).values
        assertEquals(ControlValue.Text(name), row["name"])
        assertFalse(ControlProtocolCodec.encodeResult(listed).contains("PROFILE_SECRET"))
        val shown = execute(ControlOperationId.LOCATIONS_SHOW, mapOf("selector" to ControlValue.Text(name)))
        assertEquals(ControlValue.Text(com.kardinal.vpncontrol.data.LocationConfigs.prettyStoredLocation(raw)), shown.data["configuration"])
        assertEquals(2, snapshots)
        for (result in listOf(listed, shown)) {
            assertEquals(ControlCode.OK, result.code)
            assertEquals(29, result.configurationRevision)
            assertEquals("request", result.requestId)
        }
        val missing = execute(ControlOperationId.LOCATIONS_SHOW, mapOf("selector" to ControlValue.Text("UNKNOWN_SECRET")))
        assertEquals(ControlCode.NOT_FOUND, missing.code)
        assertEquals(29, missing.configurationRevision)
        assertFalse(ControlProtocolCodec.encodeResult(missing).contains("UNKNOWN_SECRET"))
    }

    @Test fun pendingMetadataIsTrueWhenKnownAndExplicitlyUnavailableForUnmatchedRuntime() = runTest {
        val observer = AndroidRuntimeObserver()
        val current = PersistedState(appMode = AppMode.PROXY_ONLY)
        val reader = AndroidControlReader("owner", { current }, runtimeObservation = { observer.state.value },
            pendingRestart = observer::pendingRestart)
        observer.started(Any(), AppMode.PROXY_ONLY, "unknown-sticky-config")
        assertTrue("PENDING_RESTART_STATE_UNAVAILABLE" in reader.read(request(ControlOperationId.STATS)).warnings)
        val prepared = com.kardinal.vpncontrol.control.ControlRuntimeConfiguration.committed(MainUiState(appMode = AppMode.PROXY_ONLY))
        observer.started(Any(), AppMode.PROXY_ONLY, "known-config", prepared.copy(locationReference = "old-selected-reference"))
        val result = reader.read(request(ControlOperationId.STATS))
        assertTrue(result.restartRequired)
        assertFalse("PENDING_RESTART_STATE_UNAVAILABLE" in result.warnings)
        observer.resetCompleted(true)
        assertFalse(reader.read(request(ControlOperationId.STATS)).restartRequired)
    }

    @Test fun allSupportedReadsBindValuesToOneCommittedRevision() = runTest {
        var snapshots = 0
        val reader = AndroidControlReader("owner", { error("Legacy snapshot must not be used") },
            statusSnapshot = AndroidRuntimeObserver(initiallyStopped = true)::controlStatus,
            credentialPresent = { false },
            updateSnapshot = { AppUpdateState() },
            diagnosticsExport = { "Fixture diagnostics" },
            installedApps = { emptyList() },
            committedSnapshot = {
                snapshots++
                com.kardinal.vpncontrol.control.ControlCommitted("owner", 17, PersistedState(appMode = AppMode.PROXY_ONLY,
                    currentLocations = listOf("socks://127.0.0.1:1080#Fixture"),
                    subscriptions = listOf(SubscriptionSource(id = "source", url = "https://example.com/feed"))))
            })
        for (operation in AndroidControlReader.supported) {
            val arguments = when (operation) {
                ControlOperationId.SUBSCRIPTIONS_SHOW -> mapOf("id" to ControlValue.Text("source"))
                ControlOperationId.LOCATIONS_SHOW -> mapOf("selector" to ControlValue.Text("1"))
                else -> emptyMap()
            }
            val response = reader.read(request(operation, arguments))
            assertEquals(ControlCode.OK, response.code)
            assertEquals(17, response.configurationRevision)
            assertFalse(response.warnings.contains("CONFIGURATION_REVISION_UNAVAILABLE"))
        }
        assertEquals(AndroidControlReader.supported.size, snapshots)
        assertEquals(ControlValue.Text("proxy-only"), reader.read(request(ControlOperationId.SETTINGS_SHOW)).data["mode"])
    }

    @Test fun configurationReadsThroughEncodedTransportPreserveRevisionAndExplicitDisclosureBoundary() = runTest {
        var snapshots = 0
        val source = SubscriptionSource(id = "source", url = "https://example.com/?token=SECRET",
            cachedLocations = listOf("socks://user:PROFILE_SECRET@127.0.0.1:1080"))
        val reader = AndroidControlReader("owner", { error("Legacy snapshot must not be used") },
            clockMillis = { 0 }, committedSnapshot = {
                snapshots++
                com.kardinal.vpncontrol.control.ControlCommitted("owner", 19, PersistedState(
                    subscriptions = listOf(source), routingRules = RoutingRules(proxyPackages = listOf("app.browser"))))
            })
        suspend fun execute(operation: ControlOperationId, arguments: Map<String, ControlValue> = emptyMap()): ControlResult {
            val encoded = ControlProtocolCodec.encodeRequest(request(operation, arguments)).toByteArray()
            return ControlProtocolCodec.decodeResult(reader.execute(encoded, "transfer").toString(Charsets.UTF_8))
        }
        val listed = execute(ControlOperationId.SUBSCRIPTIONS_LIST)
        assertFalse(ControlProtocolCodec.encodeResult(listed).contains("SECRET"))
        val shown = execute(ControlOperationId.SUBSCRIPTIONS_SHOW, mapOf("id" to ControlValue.Text(source.id)))
        assertEquals(ControlValue.Text(source.url), shown.data["source"])
        assertFalse(ControlProtocolCodec.encodeResult(shown).contains("PROFILE_SECRET"))
        val routing = execute(ControlOperationId.ROUTING_SHOW)
        val values = (routing.data.getValue("routing") as ControlValue.ObjectValue).values
        assertEquals(listOf("app.browser"), com.kardinal.vpncontrol.data.RoutingRulesTransfer.import(
            ControlProtocolCodec.encodeValues(values)).proxyPackages)
        for (result in listOf(listed, shown, routing)) {
            assertEquals(ControlCode.OK, result.code)
            assertEquals(19, result.configurationRevision)
            assertEquals("request", result.requestId)
        }
        assertEquals(3, snapshots)
        val missing = execute(ControlOperationId.SUBSCRIPTIONS_SHOW, mapOf("id" to ControlValue.Text("UNKNOWN_SECRET")))
        assertEquals(ControlCode.NOT_FOUND, missing.code)
        assertEquals(19, missing.configurationRevision)
        assertFalse(ControlProtocolCodec.encodeResult(missing).contains("UNKNOWN_SECRET"))
        assertEquals(ControlCode.INVALID_ARGUMENT, execute(ControlOperationId.ROUTING_SHOW,
            mapOf("unexpected" to ControlValue.Text("SECRET"))).code)
    }

    @Test fun sshStatusUsesOnlyTheCapturedCommittedVersionAndNeverExposesMaterial() = runTest {
        var snapshots = 0
        val selected = PersistedState(homeSshRouteSettings = HomeSshRouteSettings(credentialVersion = 7))
        val reader = AndroidControlReader("owner", { error("Legacy snapshot must not be used") },
            committedSnapshot = {
                snapshots++
                com.kardinal.vpncontrol.control.ControlCommitted("owner", 9, selected)
            }, credentialPresent = { state ->
                assertEquals(7, state.homeSshRouteSettings.credentialVersion)
                true
            })
        val result = reader.read(request(ControlOperationId.SSH_KEY_STATUS))
        assertEquals(1, snapshots)
        assertEquals(9, result.configurationRevision)
        assertEquals(ControlCode.OK, result.code)
        assertEquals(mapOf("present" to ControlValue.BooleanValue(true)), result.data)
        val unavailable = AndroidControlReader("owner", { selected })
            .read(request(ControlOperationId.SSH_KEY_STATUS))
        assertEquals(ControlCode.UNAVAILABLE, unavailable.code)
        assertTrue(unavailable.data.isEmpty())
        assertEquals(ControlCode.INVALID_ARGUMENT, reader.read(request(ControlOperationId.SSH_KEY_STATUS,
            mapOf("path" to ControlValue.Text("private-path")))).code)
    }

    @Test fun unsupportedWritesAndOwnerConflictsDoNotReadOrMutateRepository() = runTest {
        val reader = AndroidControlReader("owner", { error("Repository must not be touched") })
        assertEquals(ControlCode.UNSUPPORTED, reader.read(request(ControlOperationId.ON)).code)
        assertEquals(ControlCode.UNSUPPORTED, reader.read(request(ControlOperationId.SETTINGS_SET)).code)
        assertEquals(ControlCode.CONFLICT, reader.read(request(ControlOperationId.SETTINGS_SHOW).copy(controllerId = "old-owner")).code)
        assertEquals(ControlCode.INVALID_ARGUMENT, reader.read(request(ControlOperationId.STATS).copy(asynchronous = true)).code)
        assertEquals(ControlCode.INVALID_ARGUMENT, reader.read(request(ControlOperationId.STATS).copy(controllerId = "owner", ifRevision = 0)).code)
        val capabilities = reader.read(request(ControlOperationId.CAPABILITIES))
        assertEquals(ControlCode.OK, capabilities.code)
        val operations = (capabilities.data.getValue("operations") as ControlValue.ArrayValue).values
            .map { (it as ControlValue.ObjectValue).values }
        val supported = operations.filter { it["supported"] == ControlValue.BooleanValue(true) }
            .map { (it.getValue("id") as ControlValue.Text).value }.toSet()
        assertEquals(AndroidControlReader.supported.map { it.wireName }.toSet(), supported)
        // STATUS is recognized, but absent authoritative status wiring cannot manufacture values.
        val unknown = AndroidControlReader("owner", { PersistedState() }).read(request(ControlOperationId.STATUS))
        assertEquals(ControlCode.UNAVAILABLE, unknown.code)
        assertEquals(ControlValue.Null, unknown.data["runtimeRunning"])
    }

    @Test fun actualPersistedSettingsAndStatsUseSharedReadProjection() = runTest {
        val reader = AndroidControlReader("owner", { PersistedState(appMode = AppMode.PROXY_ONLY, successfulStarts = 7) })
        val settings = reader.read(request(ControlOperationId.SETTINGS_SHOW))
        assertEquals(ControlValue.Text("proxy-only"), settings.data["mode"])
        assertTrue(settings.warnings.contains("CONFIGURATION_REVISION_UNAVAILABLE"))
        assertEquals(ControlValue.IntegerValue(7), reader.read(request(ControlOperationId.STATS)).data["successfulStarts"])
        assertEquals(ControlCode.NOT_FOUND, reader.read(request(ControlOperationId.SETTINGS_SHOW,
            mapOf("key" to ControlValue.Text("unknown-secret")))).code)
        for (arguments in listOf(
            mapOf("key" to ControlValue.Null),
            mapOf("key" to ControlValue.IntegerValue(1)),
            mapOf("unknown" to ControlValue.Text("mode")),
            mapOf("key" to ControlValue.Text("mode"), "extra" to ControlValue.Text("value")),
        )) {
            assertEquals(ControlCode.INVALID_ARGUMENT, reader.read(request(ControlOperationId.SETTINGS_SHOW, arguments)).code)
        }
        assertEquals(ControlCode.INVALID_ARGUMENT, reader.read(request(ControlOperationId.LOGS,
            mapOf("limit" to ControlValue.Text("-1")))).code)
    }

    @Test fun malformedUtf8AndJsonReturnSanitizedTypedFailures() = runTest {
        val reader = AndroidControlReader("owner", { error("Must not read") })
        for (bytes in listOf(byteArrayOf(0xc3.toByte(), 0x28), "private-secret".toByteArray())) {
            val encoded = reader.execute(bytes, "transfer").toString(Charsets.UTF_8)
            assertFalse(encoded.contains("private-secret"))
            val result = ControlProtocolCodec.decodeResult(encoded)
            assertEquals(ControlCode.INVALID_ARGUMENT, result.code)
            assertEquals("transfer", result.requestId)
        }
    }

    @Test fun encodedRequestPreservesRequestIdentityInResponse() = runTest {
        val reader = AndroidControlReader("owner", { PersistedState() })
        val bytes = ControlProtocolCodec.encodeRequest(request(ControlOperationId.SOURCE_SHOW)).toByteArray()
        val result = ControlProtocolCodec.decodeResult(reader.execute(bytes, "transfer").toString(Charsets.UTF_8))
        assertEquals("request", result.requestId)
        assertEquals("owner", result.controllerId)
        assertEquals(ControlCode.OK, result.code)
    }

    @Test fun persistedRunningFlagCannotInventLiveRuntimeAfterProcessDeath() = runTest {
        val reader = AndroidControlReader("new-process", { PersistedState(
            isVpnRunning = true, sessionStartedAtEpochMillis = 1000, successfulStarts = 3,
        ) }, clockMillis = { 9000 })
        val stats = reader.read(request(ControlOperationId.STATS))
        assertEquals(ControlValue.Null, stats.data["running"])
        assertEquals(ControlValue.Null, stats.data["elapsedMillis"])
        assertEquals(ControlValue.IntegerValue(3), stats.data["successfulStarts"])
        assertEquals(ControlValue.IntegerValue(1000), stats.data["startedAtEpochMillis"])
    }

    @Test fun snapshotFailureAndTimeoutKeepDecodedRequestIdentity() = runTest {
        val requestBytes = ControlProtocolCodec.encodeRequest(request(ControlOperationId.STATS)).toByteArray()
        val failed = AndroidControlReader("owner", { throw IllegalStateException("private-path-or-secret") })
        val failureJson = failed.execute(requestBytes, "transfer").toString(Charsets.UTF_8)
        assertFalse(failureJson.contains("private-path-or-secret"))
        val failure = ControlProtocolCodec.decodeResult(failureJson)
        assertEquals("request", failure.requestId)
        assertEquals(ControlCode.UNAVAILABLE, failure.code)
        val stalled = AndroidControlReader("owner", {
            kotlinx.coroutines.awaitCancellation()
        }, readTimeoutMillis = 10)
        val timeout = ControlProtocolCodec.decodeResult(stalled.execute(requestBytes, "transfer").toString(Charsets.UTF_8))
        assertEquals("request", timeout.requestId)
        assertEquals(ControlCode.TIMEOUT, timeout.code)
        assertFalse(timeout.final)
    }

    private fun request(id: ControlOperationId, args: Map<String, ControlValue> = emptyMap()) =
        ControlRequest("request", ControlCommand(id, args))
}
