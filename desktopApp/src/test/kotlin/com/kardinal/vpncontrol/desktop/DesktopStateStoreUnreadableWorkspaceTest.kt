package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.shared.ui.AppStrings
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assume.assumeTrue

/**
 * A saved workspace that exists but cannot be read is kept beside the original, never replaced or
 * deleted, and the failure is reported to the GUI and the control status. Only uses API that the
 * unfixed store already had, so the same tests reproduce the data loss on the unfixed source.
 */
class DesktopStateStoreUnreadableWorkspaceTest {
    private val truncated = "{\"persisted_state\": {\"subscriptions\": [".toByteArray()

    @Test
    fun undecodableWorkspaceIsKeptAsideAndReportedInsteadOfBeingReplacedWithDefaults() = withDirectory { directory ->
        Files.write(directory.resolve(PRIMARY), truncated)

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "the unreadable workspace was not kept: ${names(directory)}")
        assertEquals(PRIMARY, originalName(copy))
        assertContentEquals(truncated, Files.readAllBytes(copy))
        assertOwnerOnly(copy)
        assertEquals(defaultDesktopWorkspace().persistedState.subscriptions, loaded.persistedState.subscriptions)
        assertEquals(defaultDesktopWorkspace().locations, loaded.locations)
        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, copy)
        assertEquals(1, loaded.persistedState.connectionLog.count { it.message == loaded.persistedState.statusMessage })

        val reloaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())
        assertEquals(loaded.persistedState.statusMessage, reloaded.persistedState.statusMessage)
        assertEquals(1, reloaded.persistedState.connectionLog.count { it.message == loaded.persistedState.statusMessage })
        assertEquals(listOf(copy), keptCopies(directory), "a readable workspace is never kept again")
    }

    @Test
    fun firstRunStartsFromDefaultsWithoutKeepingOrReportingAnything() = withDirectory { directory ->
        val defaults = defaultDesktopWorkspace()

        val loaded = DesktopStateStore(directory).loadWorkspace(defaults)

        assertEquals(defaults, loaded)
        assertEquals(listOf(PRIMARY), names(directory))
        assertEquals(emptyList(), status(directory).warnings)
    }

    @Test
    fun undecodableRecoveryFileIsKeptWhenNoReadableCopyExists() = withDirectory { directory ->
        Files.write(directory.resolve(RECOVERY), truncated)

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "the unreadable recovery file was not kept: ${names(directory)}")
        assertEquals(RECOVERY, originalName(copy))
        assertContentEquals(truncated, Files.readAllBytes(copy))
        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, copy)
        assertTrue(Files.notExists(directory.resolve(RECOVERY), NOFOLLOW_LINKS))
    }

    @Test
    fun bothUnreadableCopiesAreKeptAndNamed() = withDirectory { directory ->
        val primary = "not json".toByteArray()
        write(directory.resolve(PRIMARY), primary, ageSeconds = 60)
        write(directory.resolve(RECOVERY), truncated, ageSeconds = 0)

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        val copies = keptCopies(directory).associateBy(::originalName)
        assertEquals(setOf(PRIMARY, RECOVERY), copies.keys, "both unreadable files must be kept: ${names(directory)}")
        assertContentEquals(primary, Files.readAllBytes(copies.getValue(PRIMARY)))
        assertContentEquals(truncated, Files.readAllBytes(copies.getValue(RECOVERY)))
        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, *copies.values.toTypedArray())
    }

    @Test
    fun newerUnreadablePrimaryIsKeptWhileTheOlderReadableRecoveryLoads() = withDirectory { directory ->
        val older = savedWorkspace("https://example.test/older")
        writeValid(directory, RECOVERY, older, ageSeconds = 60)
        write(directory.resolve(PRIMARY), truncated, ageSeconds = 0)

        val store = DesktopStateStore(directory)
        val loaded = store.loadWorkspace(defaultDesktopWorkspace())
        assertEquals(older.persistedState.subscriptions, loaded.persistedState.subscriptions)
        // The next ordinary save must not replace the newer unreadable data either.
        assertTrue(store.writeWorkspace(loaded).isSuccess)

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "the newer unreadable workspace was replaced: ${names(directory)}")
        assertEquals(PRIMARY, originalName(copy))
        assertContentEquals(truncated, Files.readAllBytes(copy))
        assertNotice(loaded.persistedState.statusMessage, OLDER_COPY_LOADED, copy)
    }

    @Test
    fun newerUnreadableRecoveryIsKeptWhileTheOlderReadablePrimaryLoads() = withDirectory { directory ->
        val older = savedWorkspace("https://example.test/older-primary")
        writeValid(directory, PRIMARY, older, ageSeconds = 60)
        write(directory.resolve(RECOVERY), truncated, ageSeconds = 0)

        val store = DesktopStateStore(directory)
        val loaded = store.loadWorkspace(defaultDesktopWorkspace())
        assertEquals(older.persistedState.subscriptions, loaded.persistedState.subscriptions)
        assertTrue(store.writeWorkspace(loaded).isSuccess)

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "the newer unreadable recovery file was deleted: ${names(directory)}")
        assertEquals(RECOVERY, originalName(copy))
        assertContentEquals(truncated, Files.readAllBytes(copy))
        assertNotice(loaded.persistedState.statusMessage, OLDER_COPY_LOADED, copy)
    }

    @Test
    fun workspaceThatCannotBeOpenedIsKeptWithoutWideningItsPermissions() = withDirectory { directory ->
        assumeTrue("POSIX permissions are required", posix(directory))
        val saved = savedWorkspace("https://example.test/unopenable")
        assertTrue(DesktopStateStore(directory).writeWorkspace(saved).isSuccess)
        val primary = directory.resolve(PRIMARY)
        val bytes = Files.readAllBytes(primary)
        Files.setPosixFilePermissions(primary, emptySet())
        assumeTrue("an unreadable file is required (not running as root)", !Files.isReadable(primary))

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "the unopenable workspace was replaced: ${names(directory)}")
        assertEquals(emptySet(), Files.getPosixFilePermissions(copy, NOFOLLOW_LINKS))
        Files.setPosixFilePermissions(copy, setOf(PosixFilePermission.OWNER_READ))
        assertContentEquals(bytes, Files.readAllBytes(copy))
        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, copy)
    }

    @Test
    fun workspaceThatCannotBeKeptIsNeitherReplacedNorReportedAsLoaded() = withDirectory { directory ->
        assumeTrue("POSIX permissions are required", posix(directory))
        val primary = directory.resolve(PRIMARY)
        Files.write(primary, truncated)
        Files.setPosixFilePermissions(directory, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE))
        try {
            assumeTrue("a read-only folder is required (not running as root)", !Files.isWritable(directory))
            assertFailsWith<DesktopPersistenceException> {
                DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())
            }
        } finally {
            Files.setPosixFilePermissions(directory, setOf(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE))
        }
        assertContentEquals(truncated, Files.readAllBytes(primary))
        assertEquals(listOf(PRIMARY), names(directory))
    }

    @Test
    fun workspaceFromANewerIncompatibleBuildIsKeptForThatBuild() = withDirectory { directory ->
        // A later format that this build cannot decode (an object where it expects a list).
        val newer = """{"format":2,"persisted_state":{"subscriptions":{"items":[{"id":"s1","url":"https://example.test/n"}]}}}"""
            .toByteArray()
        Files.write(directory.resolve(PRIMARY), newer)

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "the newer workspace was destroyed by an older build: ${names(directory)}")
        assertContentEquals(newer, Files.readAllBytes(copy))
        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, copy)
    }

    @Test
    fun newerAdditiveFieldsStillLoadWithoutBeingKeptOrReported() = withDirectory { directory ->
        val saved = savedWorkspace("https://example.test/additive")
        assertTrue(DesktopStateStore(directory).writeWorkspace(saved).isSuccess)
        val primary = directory.resolve(PRIMARY)
        val root = Json.parseToJsonElement(Files.readString(primary)).jsonObject
        val persisted = root.getValue("persisted_state").jsonObject
        Files.writeString(primary, JsonObject(root + mapOf(
            "future_top_level" to JsonPrimitive(true),
            "persisted_state" to JsonObject(persisted + ("future_setting" to JsonPrimitive("x"))),
        )).toString())

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        assertEquals(saved.persistedState.subscriptions, loaded.persistedState.subscriptions)
        assertEquals(saved.persistedState.statusMessage, loaded.persistedState.statusMessage)
        assertEquals(emptyList(), keptCopies(directory))
        assertEquals(emptyList(), status(directory).warnings)
    }

    @Test
    fun controlStatusWarnsWhileAKeptUnreadableWorkspaceRemains() = withDirectory { directory ->
        Files.write(directory.resolve(PRIMARY), truncated)

        val first = status(directory)
        assertEquals(ControlCode.OK, first.code)
        assertTrue(UNREADABLE_WARNING in first.warnings, "status warnings were ${first.warnings}")
        // A later owner of the same folder (a new transient controller) still reports the kept copy.
        assertTrue(UNREADABLE_WARNING in status(directory).warnings)

        keptCopies(directory).forEach(Files::delete)
        assertEquals(emptyList(), status(directory).warnings)
    }

    @Test
    fun guiPresentationCarriesTheNoticeWithTheKeptName() = withDirectory { directory ->
        Files.write(directory.resolve(PRIMARY), truncated)

        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val status = service.controlPresentationSnapshot("owner").frontend.activity.status

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "the unreadable workspace was not kept: ${names(directory)}")
        assertEquals(DEFAULTS_LOADED, status?.key?.name)
        assertEquals(listOf(copy.fileName.toString()), status?.args)
        val text = AppStrings(AppLanguage.ENGLISH).statusMessage(
            StatusMessages.encode(status!!.key, *status.args.toTypedArray()))
        assertTrue(copy.fileName.toString() in text && "{0}" !in text && !text.startsWith("vpn-control-status"), text)
    }

    private fun status(directory: Path): ControlResult = runBlocking {
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)))
        try {
            owner.submit(ControlRequest("status", ControlCommand(ControlOperationId.STATUS), controllerId = owner.controllerId))
        } finally {
            owner.close()
        }
    }

    private fun assertNotice(message: String, key: String, vararg copies: Path) {
        val decoded = assertNotNull(StatusMessages.decode(message), "status was not a typed notice: $message")
        assertEquals(key, decoded.key.name)
        assertEquals(1, decoded.args.size)
        copies.forEach { copy -> assertTrue(copy.fileName.toString() in decoded.args.single(), decoded.args.single()) }
        val english = AppStrings(AppLanguage.ENGLISH).statusMessage(message)
        assertTrue("{0}" !in english && !english.startsWith("vpn-control-status"), english)
        copies.forEach { copy -> assertTrue(copy.fileName.toString() in english, english) }
    }

    private fun assertOwnerOnly(file: Path) {
        if (!posix(file.parent)) return
        val permissions = Files.getPosixFilePermissions(file, NOFOLLOW_LINKS)
        assertTrue(permissions.all { it.name.startsWith("OWNER_") }, "kept copy is not owner-only: $permissions")
    }

    private fun savedWorkspace(url: String) = DesktopWorkspace(
        PersistedState(
            profileUrl = url,
            activeSubscriptionId = "saved",
            subscriptions = listOf(SubscriptionSource(id = "saved", url = url, customName = "Saved")),
        ),
        emptyList(),
    )

    private fun writeValid(directory: Path, name: String, workspace: DesktopWorkspace, ageSeconds: Long) {
        val source = Files.createTempDirectory("vpn-control-valid-copy")
        try {
            assertTrue(DesktopStateStore(source).writeWorkspace(workspace).isSuccess)
            write(directory.resolve(name), Files.readAllBytes(source.resolve(PRIMARY)), ageSeconds)
        } finally {
            source.toFile().deleteRecursively()
        }
    }

    private fun write(file: Path, bytes: ByteArray, ageSeconds: Long) {
        Files.write(file, bytes)
        Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() - ageSeconds * 1_000))
    }

    private fun keptCopies(directory: Path): List<Path> = Files.list(directory).use { entries ->
        entries.filter { entry ->
            val name = entry.fileName.toString()
            name != PRIMARY && name != RECOVERY && (name.startsWith("$PRIMARY.") || name.startsWith("$RECOVERY."))
        }.sorted().toList()
    }

    private fun originalName(copy: Path): String = copy.fileName.toString().substringBefore(".unreadable-")

    private fun names(directory: Path): List<String> =
        Files.list(directory).use { entries -> entries.map { it.fileName.toString() }.sorted().toList() }

    private fun posix(path: Path): Boolean = "posix" in path.fileSystem.supportedFileAttributeViews()

    private fun withDirectory(block: (Path) -> Unit) {
        val directory = Files.createTempDirectory("vpn-control-unreadable-workspace")
        try {
            block(directory)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private companion object {
        const val PRIMARY = "workspace.json"
        const val RECOVERY = "workspace-recovery.json"
        const val DEFAULTS_LOADED = "SAVED_SETTINGS_UNREADABLE_DEFAULTS_LOADED"
        const val OLDER_COPY_LOADED = "SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED"
        const val UNREADABLE_WARNING = "UNREADABLE_WORKSPACE_KEPT"
    }
}
