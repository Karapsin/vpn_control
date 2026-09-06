package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopFrontendSettingsDraftsTest {
    @Test
    fun modeDraftsAreGuardedRetryableAndNeverRestartRunningRuntime() = runTest {
        for (platform in listOf(ControlPlatform.LINUX, ControlPlatform.MACOS)) {
            val directory = Files.createTempDirectory("vpn-control-mode-draft")
            var runtimeEffects = 0
            val runtime = object : DesktopRuntimeController {
                override suspend fun start(profile: ProxyProfile, routingRules: RoutingRules, dnsSettings: DnsSettings,
                    appMode: AppMode, activeVerificationPort: Int?, homeSshRouteSettings: HomeSshRouteSettings): Result<DesktopRuntimeSession> {
                    runtimeEffects++; error("Must not restart")
                }
                override suspend fun stop(): Result<Unit> { runtimeEffects++; error("Must not stop") }
                override fun isRunning() = true
                override fun currentMode() = AppMode.PROXY_ONLY
                override fun currentPort(): Int? = null
            }
            val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
                initialWorkspace = DesktopWorkspace(PersistedState(appMode = AppMode.PROXY_ONLY), emptyList()),
                controlPlatform = platform, runtimeController = runtime, forceRunningState = true)
            val owner = DesktopControllerOwner(service, scope = CoroutineScope(backgroundScope.coroutineContext +
                SupervisorJob(backgroundScope.coroutineContext[Job])))
            try {
                suspend fun open() = DesktopSettingsDraft.from(DesktopSettingsDraftGroup.MODE,
                    owner.submit(ControlRequest(java.util.UUID.randomUUID().toString(), ControlCommand(ControlOperationId.SETTINGS_SHOW),
                        controllerId = owner.controllerId)))
                val first = open()
                val second = open()
                val noop = owner.submit(first.request().getOrThrow())
                assertEquals(first.revision, noop.configurationRevision)
                val vpn = first.edit("mode", "vpn")
                assertEquals(AppMode.VPN, vpn.overlay(service.state).appMode)
                assertEquals(AppMode.PROXY_ONLY, service.state.appMode)
                val result = owner.submit(vpn.request().getOrThrow())
                assertEquals(if (platform == ControlPlatform.MACOS) ControlCode.UNSUPPORTED else ControlCode.OK, result.code)
                assertEquals(result, owner.submit(vpn.copy(failure = ControlCode.TIMEOUT).request().getOrThrow()))
                if (platform == ControlPlatform.LINUX) {
                    assertEquals(ControlCode.CONFLICT, owner.submit(second.request().getOrThrow()).code)
                    assertEquals("proxy-only", second.fields["mode"])
                    assertEquals(AppMode.VPN, service.state.appMode)
                } else {
                    assertEquals(AppMode.PROXY_ONLY, service.state.appMode)
                    assertEquals(first.revision, service.controlMetadata().configurationRevision)
                }
                assertEquals(0, runtimeEffects)
                assertTrue(service.state.isVpnRunning)
            } finally { owner.close(); directory.toFile().deleteRecursively() }
        }
    }

    @Test
    fun sshRestartPromptUsesCommitResultEvenWhileRemoteSnapshotIsStale() = runTest {
        val directory = Files.createTempDirectory("vpn-control-ssh-commit-result")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val opened = owner.submit(ControlRequest("open", ControlCommand(ControlOperationId.SETTINGS_SHOW),
                controllerId = owner.controllerId))
            val request = DesktopSettingsDraft.from(DesktopSettingsDraftGroup.SSH, opened).request().getOrThrow()
            val remote = object : com.kardinal.vpncontrol.control.ControlSession by owner {
                override suspend fun submit(request: ControlRequest) = ControlResult(owner.controllerId,
                    request.requestId, ControlCode.OK, 7, restartRequired = true)
            }
            assertFalse(remote.snapshots.value.restartRequired)
            val committed = submitFrontendSettingsResult(request, remote) { _, _ -> error("No preview write") }
            assertTrue(frontendSettingsNeedsRestart(DesktopSettingsDraftGroup.SSH, committed))
            assertEquals(7L, committed.configurationRevision)
            assertFalse(frontendSettingsNeedsRestart(DesktopSettingsDraftGroup.LANGUAGE, committed))
            assertFalse(frontendSettingsNeedsRestart(DesktopSettingsDraftGroup.SSH, committed.copy(code = ControlCode.CONFLICT)))
            val preview = submitFrontendSettingsResult(request, null) { _, _ ->
                DesktopControlWriteResponse(DesktopCliResponse.success("Saved"), DesktopControlMetadata(9, true))
            }
            assertEquals(9L, preview.configurationRevision)
            assertTrue(frontendSettingsNeedsRestart(DesktopSettingsDraftGroup.SSH, preview))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun languageAndSshRemainLocalGuardedAndRetryable() = runTest {
        val directory = Files.createTempDirectory("vpn-control-language-ssh-drafts")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            suspend fun open(group: DesktopSettingsDraftGroup) = DesktopSettingsDraft.from(group,
                owner.submit(ControlRequest(java.util.UUID.randomUUID().toString(), ControlCommand(ControlOperationId.SETTINGS_SHOW),
                    controllerId = owner.controllerId)))
            val language = open(DesktopSettingsDraftGroup.LANGUAGE).edit("language", "en")
            val ssh = open(DesktopSettingsDraftGroup.SSH).edit("ssh.host", " ssh://private.example/ ")
                .edit("ssh.user", " user ")
            assertEquals(AppLanguage.SYSTEM, service.state.appLanguage)
            assertEquals("", service.state.homeSshRouteSettings.host)
            assertEquals(" ssh://private.example/ ", ssh.overlay(service.state).homeSshHostDraft)
            assertEquals(AppLanguage.ENGLISH, language.overlay(service.state).appLanguage)
            val selected = owner.submit(language.request().getOrThrow())
            assertEquals(ControlCode.OK, selected.code)
            assertEquals(selected, owner.submit(language.copy(failure = ControlCode.TIMEOUT).request().getOrThrow()))
            assertEquals(ControlCode.CONFLICT, owner.submit(ssh.request().getOrThrow()).code)
            assertEquals(" ssh://private.example/ ", ssh.fields["ssh.host"])
            val reopened = open(DesktopSettingsDraftGroup.SSH).edit("ssh.host", ssh.fields.getValue("ssh.host"))
                .edit("ssh.user", " user ")
            val saved = owner.submit(reopened.request().getOrThrow())
            assertEquals(ControlCode.OK, saved.code)
            assertEquals("private.example", service.state.homeSshRouteSettings.host)
            assertEquals("user", service.state.homeSshRouteSettings.user)
            assertEquals(saved, owner.submit(reopened.request().getOrThrow()))
            assertFalse(reopened.toString().contains("private.example"))
            assertFalse(service.state.showHomeSshRouteDialog)
            assertTrue(reopened.edit("ssh.port", "not a port").request().isFailure)
            val enabledWithoutKey = open(DesktopSettingsDraftGroup.SSH).edit("ssh.enabled", "true")
            assertEquals(ControlCode.INVALID_ARGUMENT, owner.submit(enabledWithoutKey.request().getOrThrow()).code)
            assertFalse(service.state.homeSshRouteSettings.enabled)
            val beforeImport = open(DesktopSettingsDraftGroup.SSH).edit("ssh.user", "unsaved user")
            val key = "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-PRIVATE-INPUT\n-----END OPENSSH PRIVATE KEY-----\n"
            assertTrue(owner.session.execute(DesktopCliCommand.SshKeyImport(key)).success)
            assertEquals(ControlCode.CONFLICT, owner.submit(beforeImport.request().getOrThrow()).code)
            assertEquals("unsaved user", beforeImport.fields["ssh.user"])
            assertEquals("user", service.state.homeSshRouteSettings.user)
            assertFalse(beforeImport.toString().contains("SYNTHETIC-PRIVATE-INPUT"))
            assertFalse(Files.readString(directory.resolve("workspace.json")).contains("SYNTHETIC-PRIVATE-INPUT"))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun validationAndRefreshDraftsRetainInputNormalizeAndDeduplicate() = runTest {
        val directory = Files.createTempDirectory("vpn-control-settings-drafts")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            suspend fun open(group: DesktopSettingsDraftGroup) = DesktopSettingsDraft.from(group,
                owner.submit(ControlRequest(java.util.UUID.randomUUID().toString(),
                    ControlCommand(ControlOperationId.SETTINGS_SHOW), controllerId = owner.controllerId)))
            val validation = open(DesktopSettingsDraftGroup.VALIDATION)
            val refresh = open(DesktopSettingsDraftGroup.REFRESH).edit("refresh.policy", "custom")
                .edit("refresh.custom-hours", "1,5")
            val noop = owner.submit(validation.request().getOrThrow())
            assertEquals(ControlCode.OK, noop.code)
            assertEquals(validation.revision, noop.configurationRevision)
            val edited = validation.edit("validation.batch-size", "999999")
                .edit("validation.retry-count", "invalid")
            val committed = owner.submit(edited.request().getOrThrow())
            assertEquals(ControlCode.OK, committed.code)
            assertEquals(committed, owner.submit(edited.copy(failure = ControlCode.TIMEOUT).request().getOrThrow()))
            assertEquals(com.kardinal.vpncontrol.MainDraftLogic.resolveValidationSettingsSave(
                edited.overlay(com.kardinal.vpncontrol.MainUiState())).settings, service.state.validationSettings)
            assertNotEquals(edited.request().getOrThrow().requestId,
                edited.edit("validation.batch-size", "999998").request().getOrThrow().requestId)
            assertEquals(ControlCode.CONFLICT, owner.submit(refresh.request().getOrThrow()).code)
            assertEquals("1,5", refresh.fields["refresh.custom-hours"])
            assertFalse(service.state.showRefreshPolicyDialog)
            assertFalse(service.state.showValidationSettingsDialog)
            val reopened = open(DesktopSettingsDraftGroup.REFRESH).edit("refresh.policy", "custom")
                .edit("refresh.custom-hours", "1,5")
            assertNotEquals(refresh.request().getOrThrow().requestId, reopened.request().getOrThrow().requestId)
            val refreshed = owner.submit(reopened.request().getOrThrow())
            assertEquals(ControlCode.OK, refreshed.code)
            assertEquals(1.5, service.state.subscriptionRefreshCustomHours)
            assertEquals(refreshed, owner.submit(reopened.request().getOrThrow()))
            assertTrue(reopened.edit("refresh.custom-hours", "invalid").request().isFailure)
            assertTrue(reopened.edit("refresh.custom-hours", "0.0001").request().isFailure)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun lostResponseRetryReturnsOriginalResultAndEditedOrReopenedDraftHasNewIdentity() = runTest {
        val directory = Files.createTempDirectory("vpn-control-dns-retry")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val opened = owner.submit(ControlRequest("open", ControlCommand(ControlOperationId.SETTINGS_SHOW),
                controllerId = owner.controllerId))
            val draft = DesktopDnsDraft.from(opened).copy(mode = DnsMode.CUSTOM_DOH, endpoint = "https://first.example")
            val original = owner.submit(draft.request()) // Committed, but imagine the response was lost.
            assertEquals(ControlCode.OK, original.code)
            val retry = draft.copy(failure = ControlCode.OUTCOME_UNKNOWN)
            assertEquals(draft.request().requestId, retry.request().requestId)
            assertEquals(original, owner.submit(retry.request()))
            assertEquals(1L, service.controlMetadata().configurationRevision)
            assertEquals(1, owner.snapshots.value.operations.size)
            val edited = draft.copy(endpoint = "https://second.example")
            assertNotEquals(draft.request().requestId, edited.request().requestId)
            assertEquals(ControlCode.CONFLICT, owner.submit(edited.request()).code)
            val reopened = DesktopDnsDraft.from(opened).copy(mode = draft.mode, endpoint = draft.endpoint)
            assertNotEquals(draft.request().requestId, reopened.request().requestId)
            assertFalse(draft.request().requestId.contains("first.example"))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun twoFrontendsKeepDnsInputLocalAndStaleSaveNeverRebases() = runTest {
        val directory = Files.createTempDirectory("vpn-control-local-dns")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            suspend fun open(id: String) = DesktopDnsDraft.from(owner.submit(ControlRequest(id,
                ControlCommand(ControlOperationId.SETTINGS_SHOW), controllerId = owner.controllerId)))
            val first = open("first").copy(mode = DnsMode.CUSTOM_DOH, endpoint = "https://first.example")
            val second = open("second").copy(mode = DnsMode.CUSTOM_DOT, endpoint = "tls://second.example")
            assertEquals("", service.state.customDnsEndpointDraft)
            assertEquals(DnsMode.AUTOMATIC, service.state.dnsSettings.mode)
            assertFalse(service.state.showDnsDialog)
            assertEquals(ControlCode.OK, owner.submit(first.request()).code)
            assertEquals("https://first.example/dns-query", service.state.dnsSettings.endpoint)
            val committedServiceDraft = service.state.customDnsEndpointDraft
            assertEquals("tls://second.example", second.endpoint)
            val conflict = owner.submit(second.request())
            assertEquals(ControlCode.CONFLICT, conflict.code)
            val retained = second.copy(failure = conflict.code)
            assertEquals(second.revision, retained.revision)
            assertEquals(second.endpoint, retained.endpoint)
            assertEquals(ControlCode.CONFLICT, owner.submit(retained.request()).code)
            assertEquals(committedServiceDraft, service.state.customDnsEndpointDraft)
            assertFalse(service.state.showDnsDialog)
            assertEquals("https://first.example/dns-query", service.state.dnsSettings.endpoint)
            val reopened = open("reopened")
            assertTrue(reopened.revision > second.revision)
            assertEquals("https://first.example/dns-query", reopened.endpoint)
            assertFalse(retained.toString().contains("second.example"))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun staleOwnerAndInvalidDnsDoNotCommit() = runTest {
        val directory = Files.createTempDirectory("vpn-control-local-dns-epoch")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = CoroutineScope(backgroundScope.coroutineContext +
            SupervisorJob(backgroundScope.coroutineContext[Job])))
        try {
            val draft = DesktopDnsDraft.from(owner.submit(ControlRequest("open",
                ControlCommand(ControlOperationId.SETTINGS_SHOW), controllerId = owner.controllerId)))
            assertEquals(ControlCode.CONFLICT, owner.submit(draft.copy(controllerId = "previous-owner").request()).code)
            assertEquals(ControlCode.INVALID_ARGUMENT, owner.submit(draft.copy(mode = DnsMode.CUSTOM_DOH,
                endpoint = "http://insecure.example").request()).code)
            assertEquals(draft.revision, service.controlMetadata().configurationRevision)
            assertEquals(DnsMode.AUTOMATIC, service.state.dnsSettings.mode)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}
