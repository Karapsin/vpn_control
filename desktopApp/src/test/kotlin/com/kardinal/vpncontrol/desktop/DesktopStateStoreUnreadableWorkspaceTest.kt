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
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
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
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assume.assumeTrue

/**
 * A saved workspace that exists but cannot be read is kept beside the original, never replaced or
 * deleted, and the failure is reported to the GUI and the control status. Only uses API that the
 * unfixed store already had, so the same tests reproduce the data loss on the unfixed source. Faults
 * that a real folder cannot produce on demand (a sharing lock, a full disk, a flaky mount) come from
 * [FaultInjectingFileSystem] under the unchanged store.
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
        assertLoadSavedTheNotice(directory, loaded)
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
        assertLoadSavedTheNotice(directory, loaded)
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

    // A load is interrupted after keeping: the save of the notice fails (a full disk) or the process dies.

    @Test
    fun keptCopyIsReportedOnTheNextStartWhenTheSaveAfterKeepingFails() = withDirectory { directory ->
        Files.write(directory.resolve(PRIMARY), truncated)
        val diskFull = FaultInjectingFileSystem { fault, path ->
            if (fault == FileFault.CREATE && path.fileName.toString().endsWith(".tmp")) IOException("No space left on device") else null
        }

        assertFailsWith<DesktopPersistenceException> {
            DesktopStateStore(diskFull.path(directory)).loadWorkspace(defaultDesktopWorkspace())
        }
        val kept = keptCopies(directory).singleOrNull()
        assertNotNull(kept, "the unreadable workspace was not kept before the save: ${names(directory)}")
        assertContentEquals(truncated, Files.readAllBytes(kept))

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, kept)
        assertEquals(listOf(kept), keptCopies(directory))
    }

    @Test
    fun keptCopyOfAnInterruptedLoadIsReportedWhenNoSavedCopyRemains() = withDirectory { directory ->
        val kept = directory.resolve("$PRIMARY.unreadable-20261113T101500Z-0badc0de")
        Files.write(kept, truncated)

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, kept)
        assertEquals(listOf(kept), keptCopies(directory))
        assertContentEquals(truncated, Files.readAllBytes(kept))
        val reloaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())
        assertEquals(loaded.persistedState.statusMessage, reloaded.persistedState.statusMessage)
        assertEquals(1, reloaded.persistedState.connectionLog.count { it.message == loaded.persistedState.statusMessage })
    }

    @Test
    fun keptCopyOfAnInterruptedLoadIsReportedWhenAnOlderCopyLoads() = withDirectory { directory ->
        val older = savedWorkspace("https://example.test/older-than-kept")
        writeValid(directory, RECOVERY, older, ageSeconds = 60)
        val kept = directory.resolve("$PRIMARY.unreadable-20261113T101500Z-0badc0de")
        write(kept, truncated, ageSeconds = 0)

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        assertEquals(older.persistedState.subscriptions, loaded.persistedState.subscriptions)
        assertNotice(loaded.persistedState.statusMessage, OLDER_COPY_LOADED, kept)
        assertLoadSavedTheNotice(directory, loaded)
        assertEquals(listOf(kept), keptCopies(directory))
    }

    // A saved copy whose existence cannot be determined (an I/O or stale-handle error) is not a missing one.

    @Test
    fun workspaceWhoseExistenceCannotBeDeterminedIsNeitherReplacedNorKept() = withDirectory { directory ->
        assertTrue(DesktopStateStore(directory).writeWorkspace(savedWorkspace("https://example.test/flaky-mount")).isSuccess)
        val bytes = Files.readAllBytes(directory.resolve(PRIMARY))
        val flakyMount = FaultInjectingFileSystem { fault, path ->
            if (fault == FileFault.ATTRIBUTES && path.fileName.toString() == PRIMARY) IOException("Stale file handle") else null
        }

        assertFailsWith<DesktopPersistenceException> {
            DesktopStateStore(flakyMount.path(directory)).loadWorkspace(defaultDesktopWorkspace())
        }

        assertContentEquals(bytes, Files.readAllBytes(directory.resolve(PRIMARY)), "the workspace was replaced")
        assertEquals(listOf(PRIMARY), names(directory).filter { it != ERROR_LOG })
    }

    @Test
    fun briefMetadataFailureIsRetriedAndTheWorkspaceLoads() = withDirectory { directory ->
        val saved = savedWorkspace("https://example.test/brief-metadata-failure")
        assertTrue(DesktopStateStore(directory).writeWorkspace(saved).isSuccess)
        var failures = 2
        val flakyMount = FaultInjectingFileSystem { fault, path ->
            if (fault == FileFault.ATTRIBUTES && path.fileName.toString() == PRIMARY && failures > 0) {
                failures--
                IOException("Input/output error")
            } else {
                null
            }
        }

        val loaded = DesktopStateStore(flakyMount.path(directory)).loadWorkspace(defaultDesktopWorkspace())

        assertEquals(saved.persistedState.subscriptions, loaded.persistedState.subscriptions)
        assertEquals(emptyList(), keptCopies(directory))
    }

    // A newer build marks an incompatible change with a higher format; this build keeps such a workspace.

    @Test
    fun workspaceOfAnotherFormatIsKeptEvenWhenItsFieldsWouldDecode() = withDirectory { directory ->
        val newer = (
            """{"format":2,"persisted_state":{"profile_url":"https://example.test/format-two",""" +
                """"subscriptions":[{"id":"s1","url":"https://example.test/format-two"}]},"locations":[]}"""
            ).toByteArray()
        Files.write(directory.resolve(PRIMARY), newer)

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "a workspace of another format was read as this build's: ${names(directory)}")
        assertContentEquals(newer, Files.readAllBytes(copy))
        assertEquals(defaultDesktopWorkspace().persistedState.subscriptions, loaded.persistedState.subscriptions)
        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, copy)
    }

    @Test
    fun savedWorkspaceRecordsItsFormatAndOneWithoutAFormatStillLoads() = withDirectory { directory ->
        val saved = savedWorkspace("https://example.test/format-one")
        assertTrue(DesktopStateStore(directory).writeWorkspace(saved).isSuccess)
        val primary = directory.resolve(PRIMARY)
        val root = Json.parseToJsonElement(Files.readString(primary)).jsonObject
        assertEquals(JsonPrimitive(1), root["format"], "the saved workspace does not record its format")
        Files.writeString(primary, JsonObject(root - "format").toString())

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        assertEquals(saved.persistedState.subscriptions, loaded.persistedState.subscriptions)
        assertEquals(emptyList(), keptCopies(directory))
    }

    @Test
    fun runningOwnerStopsWarningOnceTheKeptCopyIsDeleted() = withDirectory { directory ->
        Files.write(directory.resolve(PRIMARY), truncated)
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)))
        try {
            assertTrue(UNREADABLE_WARNING in status(owner).warnings)
            keptCopies(directory).forEach(Files::delete)
            assertEquals(emptyList(), status(owner).warnings, "a running owner still warned about a deleted copy")
        } finally {
            owner.close()
        }
    }

    // The keep fallbacks: an owner-only copy when the rename is refused, and nothing written when neither works.

    @Test
    fun workspaceThatCannotBeRenamedIsCopiedPrivatelyBeforeTheDefaultsReplaceIt() = withDirectory { directory ->
        Files.write(directory.resolve(PRIMARY), truncated)
        val sharingLock = FaultInjectingFileSystem { fault, path ->
            if (fault == FileFault.MOVE && path.fileName.toString() == PRIMARY) IOException("The file is in use") else null
        }

        val loaded = DesktopStateStore(sharingLock.path(directory)).loadWorkspace(defaultDesktopWorkspace())

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "the workspace that could not be renamed was not copied: ${names(directory)}")
        assertContentEquals(truncated, Files.readAllBytes(copy))
        if (posix(directory)) {
            // Owner-only from creation, whatever the umask (a umask-dependent copy would expose private data).
            val ownerOnly = PosixFilePermissions.fromString("rw-------")
            val requested = sharingLock.permissionsRequestedAtCreation(copy.fileName.toString())
            assertEquals(ownerOnly, requested, "the copy was not created owner-only")
            assertEquals(ownerOnly, Files.getPosixFilePermissions(copy, NOFOLLOW_LINKS))
        }
        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, copy)
        assertEquals(loaded.persistedState.statusMessage, savedStatus(directory.resolve(PRIMARY)))
    }

    @Test
    fun workspaceThatCanNeitherBeRenamedNorCopiedFailsClosedWhileTheFolderStaysWritable() = withDirectory { directory ->
        Files.write(directory.resolve(PRIMARY), truncated)
        val exclusiveLock = FaultInjectingFileSystem { fault, path ->
            val locked = path.fileName.toString() == PRIMARY && (fault == FileFault.MOVE || fault == FileFault.READ)
            if (locked) IOException("The file is in use") else null
        }

        assertFailsWith<DesktopPersistenceException> {
            DesktopStateStore(exclusiveLock.path(directory)).loadWorkspace(defaultDesktopWorkspace())
        }

        assertContentEquals(truncated, Files.readAllBytes(directory.resolve(PRIMARY)), "the workspace was replaced")
        assertEquals(setOf(PRIMARY, ERROR_LOG), names(directory).toSet(), "only the error class may be written")
        val log = Files.readString(directory.resolve(ERROR_LOG))
        assertTrue("PERSISTENCE_FAILED" in log && directory.toString() !in log, log)
    }

    // The strict UTF-8 rule and read retries.

    @Test
    fun workspaceThatIsNotValidUtf8IsKeptByteForByte() = withDirectory { directory ->
        writeValid(directory, PRIMARY, savedWorkspace("https://example.test/utf8"), ageSeconds = 0)
        val primary = directory.resolve(PRIMARY)
        val valid = Files.readAllBytes(primary)
        val at = indexOf(valid, "\"Saved\"".toByteArray())
        assertTrue(at >= 0)
        // "Sÿved" as one raw 0xFF byte: never valid UTF-8, inside an otherwise valid workspace.
        val invalid = valid.copyOf().also { it[at + 2] = 0xFF.toByte() }
        Files.write(primary, invalid)

        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())

        val copy = keptCopies(directory).singleOrNull()
        assertNotNull(copy, "a workspace that is not valid UTF-8 was decoded and would be rewritten: ${names(directory)}")
        assertContentEquals(invalid, Files.readAllBytes(copy))
        assertNotice(loaded.persistedState.statusMessage, DEFAULTS_LOADED, copy)
    }

    @Test
    fun briefReadFailureIsRetriedInsteadOfKeepingAReadableWorkspace() = withDirectory { directory ->
        val saved = savedWorkspace("https://example.test/brief-read-failure")
        assertTrue(DesktopStateStore(directory).writeWorkspace(saved).isSuccess)
        var failures = 2
        val briefLock = FaultInjectingFileSystem { fault, path ->
            if (fault == FileFault.READ && path.fileName.toString() == PRIMARY && failures > 0) {
                failures--
                IOException("The file is in use")
            } else {
                null
            }
        }

        val loaded = DesktopStateStore(briefLock.path(directory)).loadWorkspace(defaultDesktopWorkspace())

        assertEquals(saved.persistedState.subscriptions, loaded.persistedState.subscriptions)
        assertEquals(saved.persistedState.statusMessage, loaded.persistedState.statusMessage)
        assertEquals(emptyList(), keptCopies(directory), "a readable workspace was kept after a brief read failure")
    }

    private fun status(directory: Path): ControlResult {
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)))
        try {
            return status(owner)
        } finally {
            owner.close()
        }
    }

    private fun status(owner: DesktopControllerOwner): ControlResult = runBlocking {
        owner.submit(ControlRequest("status", ControlCommand(ControlOperationId.STATUS), controllerId = owner.controllerId))
    }

    /** The load itself saved the loaded copy with its notice (a later owner shows it) and the superseded files are gone. */
    private fun assertLoadSavedTheNotice(directory: Path, loaded: DesktopWorkspace) {
        assertEquals(loaded.persistedState.statusMessage, savedStatus(directory.resolve(PRIMARY)), "the load did not save the notice")
        assertTrue(Files.notExists(directory.resolve(RECOVERY), NOFOLLOW_LINKS), "a superseded recovery file remained")
        val reloaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())
        assertEquals(loaded.persistedState.subscriptions, reloaded.persistedState.subscriptions)
        assertEquals(loaded.persistedState.statusMessage, reloaded.persistedState.statusMessage)
        assertEquals(1, reloaded.persistedState.connectionLog.count { it.message == loaded.persistedState.statusMessage })
    }

    private fun savedStatus(file: Path): String? = runCatching {
        Json.parseToJsonElement(Files.readString(file)).jsonObject.getValue("persisted_state").jsonObject
            .getValue("status_message").jsonPrimitive.content
    }.getOrNull()

    private fun indexOf(bytes: ByteArray, part: ByteArray): Int =
        (0..bytes.size - part.size).firstOrNull { start -> part.indices.all { bytes[start + it] == part[it] } } ?: -1

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
        const val ERROR_LOG = "workspace-write-error.log"
        const val DEFAULTS_LOADED = "SAVED_SETTINGS_UNREADABLE_DEFAULTS_LOADED"
        const val OLDER_COPY_LOADED = "SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED"
        const val UNREADABLE_WARNING = "UNREADABLE_WORKSPACE_KEPT"
    }
}
