package com.kardinal.vpncontrol.desktop

import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import javax.imageio.ImageIO
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Native probes of whether a located window is ready for its region to be published. */
internal interface RegionReadinessProbes {
    /** IsHungAppWindow: the window's thread has not taken a message for about five seconds. */
    fun isHungAppWindow(handle: Long): Boolean

    /** SendMessageTimeout(WM_NULL, SMTO_ABORTIFHUNG) returned within [timeoutMillis]. */
    fun answersWithin(handle: Long, timeoutMillis: Int): Boolean

    /** Every descendant window (EnumChildWindows) with its class, caption, control ID and visibility. */
    fun childWindows(handle: Long): List<NativeControl>

    /** The client rectangle in screen coordinates, or null when it cannot be read. */
    fun clientArea(handle: Long): RegionRect?
}

/** The notification area and this process's notification icon, as the Windows shell exposes them. */
internal interface NotificationAreaShell {
    /** The visible taskbar's notification area, or null without a visible taskbar. */
    fun notificationArea(): NotificationArea?

    /** Shell_NotifyIconGetRect for icon [uid] of this process's AWT tray message window. */
    fun notifyIcon(uid: Int): NotifyIconLocation

    /** HKCU\Control Panel\NotifyIconSettings entries, or null when that key is absent. */
    fun notifyIconSettings(): List<NotifyIconEntry>?

    /** Writes IsPromoted of one NotifyIconSettings entry; null deletes the value. */
    fun setNotifyIconPromoted(key: String, value: Int?)

    /** This process's executable, as Explorer records it. */
    fun processExecutable(): String

    /** A known folder's path by its GUID (no braces), for "{FOLDERID}\rest" entry paths. */
    fun knownFolderPath(guid: String): String?
}

/** Native desktop operations the region capture needs; WindowsRegionDesktop is the only real one. */
internal interface RegionDesktop : RegionReadinessProbes, NotificationAreaShell {
    fun screen(): RegionRect
    fun workArea(): RegionRect
    fun scale(): Pair<Double, Double>
    fun census(): List<NativeWindow>
    fun window(handle: Long): NativeWindow?
    fun captureScreen(screen: RegionRect): BufferedImage
    fun disableTransitions(handle: Long): Boolean
    fun stackBelow(window: Long, above: Long): Boolean
    fun showKeyboardCues(handle: Long)
    fun bringToForeground(handle: Long, pause: () -> Unit): Boolean
    fun foregroundHandle(): Long
    fun focus(handle: Long): JsonObject
    fun parkCursor(x: Int, y: Int): Boolean
    fun dismissHostedSystemProperties(pause: () -> Unit): List<String>
    fun pause(millis: Long)
}

/**
 * A surface located by native identity: its region, the window that paints it and how to re-read
 * it. A window part gets an opaque capture backdrop stacked directly beneath it, because Windows
 * blends a window's 1 px border (and any translucent pixel) with whatever lies behind it.
 */
internal data class LocatedPart(
    val role: String,
    val target: JsonObject,
    val rect: RegionRect,
    val placement: JsonObject,
    val targetHandle: Long,
    val keyboardCues: Boolean,
    val current: () -> RegionRect?,
    val backdropHandle: Long? = null,
    val readiness: PartReadiness = WindowsRegionScenes.readiness(role),
) {
    /** Everything stacked above the backdrop (or above the target without one) blends into the region. */
    val occlusion: OcclusionCheck
        get() = if (backdropHandle == null) {
            OcclusionCheck(role, rect, targetHandle, setOf(targetHandle))
        } else {
            OcclusionCheck(role, rect, backdropHandle, setOf(targetHandle, backdropHandle))
        }
}

private class CapturedRegion(val frame: BufferedImage, val image: BufferedImage, val pixels: IntArray)

private val regionJson = Json { prettyPrint = true }

/** Region capture of one scene: placement, foreground, guard, stable frame and evidence. */
internal class RegionCaptureEngine(
    private val desktop: RegionDesktop,
    private val platform: String,
    private val session: JsonObject,
) {
    /**
     * Runs [block] while the scene's surfaces are still open: a refusal raised inside it keeps the
     * full screen of that moment, so its evidence never shows a desktop the scene already closed.
     */
    fun <T> keepingRefusedMoment(block: () -> T): T = try {
        block()
    } catch (refusal: RegionCaptureRefusedException) {
        if (refusal.frame == null) {
            runCatching { desktop.captureScreen(desktop.screen()) }
                .onSuccess { refusal.frame = it }
                .onFailure(refusal::addSuppressed)
        }
        throw refusal
    }

    /** Locates a window by native identity and places its visible frame canonically. */
    fun placeWindow(
        sceneId: String,
        role: String,
        rule: TargetRule,
        canonical: CanonicalPlacement,
        move: (Long, PlacementMove, Boolean) -> Unit,
        maxPolls: Int = 80,
    ): LocatedPart = keepingRefusedMoment {
        val found = awaitTarget(sceneId, rule, maxPolls, desktop::census) { desktop.pause(250) }
        val transitionsDisabled = desktop.disableTransitions(found.handle)
        val placed = placeCanonically(
            sceneId,
            role,
            canonical,
            desktop.workArea(),
            read = {
                desktop.window(found.handle)?.takeIf(NativeWindow::paints) ?: refuseRegion(
                    sceneId, RegionCaptureRefusal.TARGET_MISSING, "$role ${hexHandle(found.handle)} disappeared during placement",
                )
            },
            move = { plan, resize -> move(found.handle, plan, resize) },
            pause = { desktop.pause(150) },
        )
        LocatedPart(
            role = role,
            target = placed.window.identity(rule.kind, rule.locator()),
            rect = placed.expected,
            placement = buildJsonObject {
                put("canonical", canonical.json())
                put("moves", placed.moves)
                put("window_rect", placed.window.windowRect.json())
                put("transitions_disabled", transitionsDisabled)
            },
            targetHandle = found.handle,
            keyboardCues = true,
            current = { desktop.window(found.handle)?.takeIf(NativeWindow::paints)?.bounds },
        )
    }

    fun capture(sceneId: String, output: Path, parts: List<LocatedPart>, foregroundHandle: Long): JsonObject {
        require(parts.isNotEmpty()) { "a region capture needs at least one part" }
        var lastFrame: BufferedImage? = null
        try {
            val (scaleX, scaleY) = desktop.scale()
            if (scaleX != 1.0 || scaleY != 1.0) {
                refuseRegion(sceneId, RegionCaptureRefusal.NON_CANONICAL_DISPLAY, "display scale is ${scaleX}x$scaleY; regions need 100%")
            }
            val screen = desktop.screen()
            val workArea = desktop.workArea()
            parts.forEach { part ->
                if (!screen.contains(part.rect)) {
                    refuseRegion(sceneId, RegionCaptureRefusal.OUTSIDE_WORK_AREA, "${part.role} region ${part.rect} is outside the screen $screen")
                }
            }
            parts.filter { it.keyboardCues }.forEach { desktop.showKeyboardCues(it.targetHandle) }
            if (!desktop.bringToForeground(foregroundHandle) { desktop.pause(100) }) {
                refuseRegion(
                    sceneId, RegionCaptureRefusal.NOT_FOREGROUND,
                    "${hexHandle(foregroundHandle)} is not foreground; foreground is ${hexHandle(desktop.foregroundHandle())}",
                )
            }
            val focus = desktop.focus(foregroundHandle)
            if (focus["focus_inside_target"]?.jsonPrimitive?.boolean != true) {
                refuseRegion(sceneId, RegionCaptureRefusal.NOT_FOREGROUND, "keyboard focus is outside ${hexHandle(foregroundHandle)}: $focus")
            }
            parts.forEach { part ->
                val backdrop = part.backdropHandle ?: return@forEach
                // The occlusion guard verifies the resulting order: a backdrop left above its
                // target hides it and is refused as an occluder, whatever this call returned.
                desktop.stackBelow(backdrop, part.targetHandle)
                val covered = desktop.window(backdrop)?.takeIf(NativeWindow::paints)?.bounds
                if (covered == null || !covered.contains(part.rect)) {
                    refuseRegion(
                        sceneId, RegionCaptureRefusal.PLACEMENT_NOT_CONVERGED,
                        "${part.role} backdrop ${hexHandle(backdrop)} at ${covered ?: "nowhere"} does not cover ${part.rect}",
                    )
                }
            }
            val cursor = cursorParkingPoint(workArea, parts.map { it.rect }) ?: refuseRegion(
                sceneId, RegionCaptureRefusal.CURSOR_NOT_PARKED, "no work-area corner is clear of ${parts.map { it.rect }}",
            )
            if (!desktop.parkCursor(cursor.first, cursor.second)) {
                refuseRegion(sceneId, RegionCaptureRefusal.CURSOR_NOT_PARKED, "cursor did not reach ${cursor.first},${cursor.second}")
            }
            val residue = desktop.dismissHostedSystemProperties { desktop.pause(250) }
            val checks = parts.map { it.occlusion }
            requireUnoccluded(sceneId, "before", desktop.census(), checks)
            // Two identical captures show only a quiet frame, not a ready target: before the loop
            // and again before publishing, every part's thread must answer and its expected
            // controls exist, and the published pair must have painted.
            val readyPolls = awaitReady(sceneId, parts)
            val clients = parts.map { clientRegion(sceneId, it) }
            val layout = stackLayout(parts.map { it.rect.width to it.rect.height })
            val stable = awaitStableFrame(
                sceneId,
                REGION_STABLE_MAX_ATTEMPTS,
                capture = {
                    val frame = desktop.captureScreen(screen)
                    lastFrame = frame
                    // A census follows every capture, so both frames of the published pair are
                    // bracketed: a window shown only while they were taken is refused as well.
                    requireUnoccluded(sceneId, "during", desktop.census(), checks)
                    val image = composeRegionImage(frame, screen, parts.map { it.rect }, layout)
                    CapturedRegion(frame, image, rgbPixels(image))
                },
                identical = { first, second -> first.pixels.contentEquals(second.pixels) },
                pause = { desktop.pause(REGION_STABLE_INTERVAL_MILLIS) },
                unpainted = { captured -> unpainted(captured.frame, screen, parts, clients) },
            )
            requireUnoccluded(sceneId, "after", desktop.census(), checks)
            parts.forEach { part ->
                val now = part.current()
                if (now != part.rect) {
                    refuseRegion(sceneId, RegionCaptureRefusal.TARGET_MOVED, "${part.role} moved from ${part.rect} to ${now ?: "nowhere"} during capture")
                }
            }
            if (desktop.foregroundHandle() != foregroundHandle) {
                refuseRegion(sceneId, RegionCaptureRefusal.NOT_FOREGROUND, "foreground changed to ${hexHandle(desktop.foregroundHandle())} during capture")
            }
            val ready = parts.map { requireReady(sceneId, it, "before publishing") }
            val record = regionRecord(
                platform = platform,
                sceneId = sceneId,
                imageWidth = layout.width,
                imageHeight = layout.height,
                screen = screen,
                workArea = workArea,
                parts = parts.mapIndexed { index, part ->
                    RegionPart(part.role, part.target, part.rect, layout.offsets[index], placementWithBackdrop(part))
                },
                stableAttempts = stable.attempts,
                maxAttempts = REGION_STABLE_MAX_ATTEMPTS,
                intervalMillis = REGION_STABLE_INTERVAL_MILLIS,
                occlusion = occlusionJson(checks),
                readiness = buildJsonObject {
                    put("phases", JsonArray(listOf(JsonPrimitive("before-stable-frame"), JsonPrimitive("before-publish"))))
                    put("polls", readyPolls)
                    put("max_polls", REGION_READY_MAX_POLLS)
                    put("response_timeout_ms", REGION_RESPONSE_TIMEOUT_MILLIS)
                    put("parts", JsonArray(ready.mapIndexed { index, evidence ->
                        JsonObject(evidence + ("client_area" to (clients[index]?.json() ?: JsonNull)) + ("painted" to JsonPrimitive(true)))
                    }))
                },
                cursor = cursor,
                foreground = buildJsonObject {
                    put("handle", hexHandle(foregroundHandle))
                    put("verified", true)
                    put("focus", focus)
                    put("dismissed_residue_remaining", residue.size)
                },
                session = session,
            )
            Files.createDirectories(output)
            writePng(stable.frame.image, output.resolve(regionImageName(sceneId)))
            writePng(stable.frame.frame, output.resolve(regionFrameName(sceneId)))
            Files.writeString(output.resolve(regionRecordName(sceneId)), regionJson.encodeToString(JsonObject.serializer(), record) + "\n")
            return record
        } catch (refusal: RegionCaptureRefusedException) {
            if (refusal.frame == null) refusal.frame = lastFrame
            writeRefusal(output, sceneId, refusal)
            throw refusal
        }
    }

    /**
     * Evidence that [part] is ready now, or the named refusal of the first check it fails: its
     * thread answers (not hung, WM_NULL within the bound) and its expected child controls show.
     */
    private fun requireReady(sceneId: String, part: LocatedPart, phase: String): JsonObject {
        val rule = part.readiness
        val window = "${part.role} ${hexHandle(part.targetHandle)}"
        if (rule.responsive) {
            if (desktop.isHungAppWindow(part.targetHandle)) {
                refuseRegion(sceneId, RegionCaptureRefusal.TARGET_NOT_RESPONDING, "$window is hung (IsHungAppWindow) $phase")
            }
            if (!desktop.answersWithin(part.targetHandle, REGION_RESPONSE_TIMEOUT_MILLIS)) {
                refuseRegion(
                    sceneId, RegionCaptureRefusal.TARGET_NOT_RESPONDING,
                    "$window did not answer WM_NULL within $REGION_RESPONSE_TIMEOUT_MILLIS ms $phase",
                )
            }
        }
        val controls = if (rule.controls.isEmpty()) emptyList() else {
            val census = desktop.childWindows(part.targetHandle)
            val missing = rule.controls.filter { wanted -> census.none(wanted::matches) }
            if (missing.isNotEmpty()) {
                refuseRegion(
                    sceneId, RegionCaptureRefusal.CONTROLS_MISSING,
                    "$window lacks ${missing.joinToString { it.describe() }} $phase; its child windows: " +
                        census.joinToString("; ") { it.describe() }.ifEmpty { "none" },
                )
            }
            rule.controls.map { wanted -> census.first(wanted::matches) }
        }
        val area = if (rule.notificationIcon) desktop.notificationArea() else null
        if (rule.notificationIcon) {
            notifyIconPlacementFailure(part.rect, area)?.let {
                refuseRegion(sceneId, RegionCaptureRefusal.TRAY_ICON_NOT_PROMOTED, "$it $phase")
            }
        }
        return buildJsonObject {
            put("role", part.role)
            put("responsive", rule.responsive)
            put("controls", JsonArray(controls.map { JsonPrimitive(it.describe()) }))
            if (area != null) put("notification_area", area.source)
        }
    }

    /** Bounded wait until every part is ready; returns the number of checks it took. */
    private fun awaitReady(sceneId: String, parts: List<LocatedPart>): Int {
        for (poll in 1 until REGION_READY_MAX_POLLS) {
            val ready = try {
                parts.forEach { requireReady(sceneId, it, "before the stable-frame loop") }
                true
            } catch (notYet: RegionCaptureRefusedException) {
                false
            }
            if (ready) return poll
            desktop.pause(REGION_READY_INTERVAL_MILLIS)
        }
        val phase = "before the stable-frame loop after $REGION_READY_MAX_POLLS checks $REGION_READY_INTERVAL_MILLIS ms apart"
        parts.forEach { requireReady(sceneId, it, phase) }
        return REGION_READY_MAX_POLLS
    }

    /** A window part's client area inside its region: the window must paint it, not only DWM its frame. */
    private fun clientRegion(sceneId: String, part: LocatedPart): RegionRect? {
        if (!part.readiness.clientPainted) return null
        val client = desktop.clientArea(part.targetHandle)?.intersect(part.rect)
        if (client == null || client.isEmpty) {
            refuseRegion(
                sceneId, RegionCaptureRefusal.TARGET_NOT_PAINTED,
                "${part.role} ${hexHandle(part.targetHandle)} has no client area inside its region ${part.rect}",
            )
        }
        return client
    }

    /** Why a capture has not painted, or null: no part's region and no window's client area is one flat colour. */
    private fun unpainted(frame: BufferedImage, screen: RegionRect, parts: List<LocatedPart>, clients: List<RegionRect?>): String? {
        parts.forEachIndexed { index, part ->
            flatColour(frame, screen, part.rect)?.let { return "${part.role} region ${part.rect} is entirely ${flatColourName(it, part)}" }
            val client = clients[index] ?: return@forEachIndexed
            flatColour(frame, screen, client)?.let { return "${part.role} client area $client is entirely ${flatColourName(it, part)}" }
        }
        return null
    }

    private fun flatColourName(rgb: Int, part: LocatedPart): String =
        if (part.backdropHandle != null && rgb == WindowsRegionScenes.BACKDROP_RGB) {
            "the capture backdrop colour ${rgbHex(rgb)}"
        } else {
            "one colour ${rgbHex(rgb)}"
        }

    private fun placementWithBackdrop(part: LocatedPart): JsonObject = JsonObject(
        part.placement + ("backdrop" to if (part.backdropHandle == null) JsonNull else buildJsonObject {
            put("handle", hexHandle(part.backdropHandle))
            put("rgb", "#%06X".format(WindowsRegionScenes.BACKDROP_RGB))
            put("stacked_below", hexHandle(part.targetHandle))
        }),
    )

    /**
     * Records a refusal raised before [capture] (for example while locating or placing a target),
     * with the frame [keepingRefusedMoment] kept before the scene closed its surfaces.
     */
    fun recordRefusal(output: Path, refusal: RegionCaptureRefusedException) {
        if (!Files.exists(output.resolve("${refusal.sceneId}.refusal.json"))) writeRefusal(output, refusal.sceneId, refusal)
    }

    /**
     * A capture session that cannot be applied refuses every requested scene like any other
     * refusal: each scene gets its named reason, and all of them name one full frame of that moment.
     */
    fun recordSessionRefusal(output: Path, scenes: List<String>, refusal: RegionCaptureRefusedException) {
        val frame = runCatching {
            Files.createDirectories(output)
            val diagnostic = refusal.frame ?: desktop.captureScreen(desktop.screen()).also { refusal.frame = it }
            writePng(diagnostic, output.resolve(SESSION_REFUSAL_FRAME))
            SESSION_REFUSAL_FRAME
        }.onFailure(refusal::addSuppressed).getOrNull()
        scenes.forEach { sceneId ->
            runCatching { writeRefusalRecord(output, sceneId, refusal, frame) }.exceptionOrNull()?.let(refusal::addSuppressed)
        }
    }

    /** Keeps the frame of the refused moment and the named reason for the reviewer. */
    private fun writeRefusal(output: Path, sceneId: String, refusal: RegionCaptureRefusedException) {
        runCatching {
            Files.createDirectories(output)
            val diagnostic = refusal.frame ?: desktop.captureScreen(desktop.screen()).also { refusal.frame = it }
            writePng(diagnostic, output.resolve(regionFrameName(sceneId)))
            writeRefusalRecord(output, sceneId, refusal, regionFrameName(sceneId))
        }.exceptionOrNull()?.let(refusal::addSuppressed)
    }

    private fun writeRefusalRecord(output: Path, sceneId: String, refusal: RegionCaptureRefusedException, frame: String?) {
        Files.createDirectories(output)
        Files.writeString(
            output.resolve("$sceneId.refusal.json"),
            regionJson.encodeToString(JsonObject.serializer(), buildJsonObject {
                put("schema_version", REGION_RECORD_SCHEMA)
                put("scene", sceneId)
                put("reason", refusal.refusal.reason)
                put("detail", JsonPrimitive(refusal.detail))
                put("frame", frame?.let(::JsonPrimitive) ?: JsonNull)
            }) + "\n",
        )
    }

    private fun writePng(image: BufferedImage, path: Path) {
        check(ImageIO.write(image, "png", path.toFile())) { "no PNG writer for $path" }
    }
}

/**
 * Runs every requested scene under one capture session (VISUAL-002). A refused scene keeps its
 * frame and named reason while the remaining scenes still run. A session that cannot be applied
 * runs no scene: every requested scene is refused with session-setting-failed beside one full
 * frame of that moment. The run fails when any scene failed.
 */
internal fun runRegionCaptureScenes(
    desktop: RegionDesktop,
    platform: String,
    settings: List<Pair<String, SessionSetting>>,
    scenes: List<String>,
    output: Path,
    captureScene: (RegionCaptureEngine, String) -> Unit,
) {
    val session = try {
        CaptureSessionSettings.applyAll(settings)
    } catch (refusal: RegionCaptureRefusedException) {
        RegionCaptureEngine(desktop, platform, JsonObject(emptyMap())).recordSessionRefusal(output, scenes, refusal)
        throw IllegalStateException("Windows region capture failed for ${scenes.size} scene(s): ${refusal.message}", refusal)
    }
    val failures = mutableListOf<Throwable>()
    session.use { applied ->
        val engine = RegionCaptureEngine(desktop, platform, applied.json())
        scenes.forEach { sceneId ->
            try {
                captureScene(engine, sceneId)
            } catch (refusal: RegionCaptureRefusedException) {
                engine.recordRefusal(output, refusal)
                failures += refusal
            } catch (error: Exception) {
                failures += error
            }
        }
    }
    if (failures.isNotEmpty()) {
        throw IllegalStateException(
            "Windows region capture failed for ${failures.size} scene(s): " +
                failures.joinToString("; ") { it.message.orEmpty() },
        ).apply { failures.forEach(::addSuppressed) }
    }
}

/** One promotion of this process's notification icon; closing it restores every value it wrote. */
internal class NotifyIconPromotion(
    val entries: List<NotifyIconEntry>,
    val rectBefore: RegionRect?,
    private val restore: () -> Unit,
) : AutoCloseable {
    fun json(): JsonObject = buildJsonObject {
        put("setting", "HKCU\\${WindowsRegionScenes.NOTIFY_ICON_SETTINGS}\\<key>\\IsPromoted")
        put("entries", JsonArray(entries.map { entry ->
            buildJsonObject {
                put("key", entry.key)
                put("original", entry.promoted?.let(::JsonPrimitive) ?: JsonNull)
                put("capture", 1)
                put("read_back", 1)
            }
        }))
        put("rect_before_promotion", rectBefore?.json() ?: JsonNull)
    }

    override fun close() = restore()
}

/**
 * Promotes this process's notification icon out of the Windows 11 overflow for the scene, failing
 * closed: an absent NotifyIconSettings key, no entry for this executable and icon within the bound,
 * or a value that does not read back as promoted refuses the scene as tray-icon-not-promoted. Values
 * written before a refusal are restored before it is raised; the caller closes the promotion.
 */
internal fun promoteNotifyIcon(
    desktop: RegionDesktop,
    sceneId: String,
    uid: Int,
    maxPolls: Int = NOTIFY_ICON_ENTRY_POLLS,
): NotifyIconPromotion {
    val executable = desktop.processExecutable()
    val rectBefore = desktop.notifyIcon(uid).rect
    var settings: List<NotifyIconEntry>? = null
    var selected = emptyList<NotifyIconEntry>()
    for (poll in 1..maxPolls) {
        // Explorer records a newly added icon's entry asynchronously.
        settings = desktop.notifyIconSettings()
        selected = settings?.let { selectNotifyIconEntries(it, executable, uid, desktop::knownFolderPath) }.orEmpty()
        if (selected.isNotEmpty()) break
        if (poll < maxPolls) desktop.pause(250)
    }
    if (settings == null) {
        refuseRegion(
            sceneId, RegionCaptureRefusal.TRAY_ICON_NOT_PROMOTED,
            "HKCU\\${WindowsRegionScenes.NOTIFY_ICON_SETTINGS} is absent after $maxPolls reads, so the icon cannot be promoted out of the overflow",
        )
    }
    if (selected.isEmpty()) {
        refuseRegion(
            sceneId, RegionCaptureRefusal.TRAY_ICON_NOT_PROMOTED,
            "no NotifyIconSettings entry for '$executable' uid=$uid appeared in $maxPolls reads of ${settings.size} entries",
        )
    }
    val written = mutableListOf<NotifyIconEntry>()
    fun restore(): IllegalStateException? {
        val failures = written.asReversed().mapNotNull { entry ->
            runCatching { desktop.setNotifyIconPromoted(entry.key, entry.promoted) }.exceptionOrNull()?.let { entry.key to it }
        }
        if (failures.isEmpty()) return null
        return IllegalStateException(
            "NotifyIconSettings IsPromoted was not restored for " + failures.joinToString { (key, error) -> "$key (${error.message})" },
        ).apply { failures.forEach { addSuppressed(it.second) } }
    }
    try {
        selected.forEach { entry ->
            desktop.setNotifyIconPromoted(entry.key, 1)
            written += entry
        }
        val readBack = desktop.notifyIconSettings().orEmpty().associateBy(NotifyIconEntry::key)
        val unverified = selected.filter { readBack[it.key]?.promoted != 1 }
        if (unverified.isNotEmpty()) {
            refuseRegion(
                sceneId, RegionCaptureRefusal.TRAY_ICON_NOT_PROMOTED,
                "IsPromoted does not read back 1 after promotion: " +
                    unverified.joinToString { "${it.key}=${readBack[it.key]?.promoted ?: "absent"}" },
            )
        }
    } catch (error: Exception) {
        val refusal = error as? RegionCaptureRefusedException
            ?: RegionCaptureRefusedException(
                sceneId, RegionCaptureRefusal.TRAY_ICON_NOT_PROMOTED, "promoting the notification icon failed: ${error.message}",
            ).apply { addSuppressed(error) }
        restore()?.let(refusal::addSuppressed)
        throw refusal
    }
    return NotifyIconPromotion(selected, rectBefore) { restore()?.let { throw it } }
}

/**
 * The promoted icon's own region: a stable, icon-sized Shell_NotifyIconGetRect result inside the
 * visible notification area, off the overflow chevron and outside any open overflow flyout. An
 * icon that never gets there is refused as tray-icon-not-promoted; no rectangle at all is
 * tray-icon-unavailable.
 */
internal fun locateNotifyIcon(
    desktop: RegionDesktop,
    sceneId: String,
    uid: Int,
    promotion: NotifyIconPromotion,
    maxPolls: Int = NOTIFY_ICON_RECT_POLLS,
): LocatedPart {
    var area = desktop.notificationArea() ?: refuseRegion(
        sceneId, RegionCaptureRefusal.TRAY_ICON_UNAVAILABLE, "no visible ${WindowsRegionScenes.TASKBAR_CLASS}",
    )
    var location = desktop.notifyIcon(uid)
    var misplaced: String? = null
    val (rect, reads) = try {
        awaitIconRect(sceneId, maxPolls, area.taskbar.bounds, read = {
            location = desktop.notifyIcon(uid)
            val now = desktop.notificationArea()
            if (now != null) area = now
            misplaced = location.rect?.let { notifyIconPlacementFailure(it, now) }
            location.rect.takeIf { misplaced == null }
        }) { desktop.pause(250) }
    } catch (unavailable: RegionCaptureRefusedException) {
        val detail = misplaced ?: throw unavailable
        refuseRegion(sceneId, RegionCaptureRefusal.TRAY_ICON_NOT_PROMOTED, "$detail after $maxPolls reads")
    }
    return LocatedPart(
        role = "tray-icon",
        target = JsonObject(location.identity + ("taskbar" to area.taskbar.identity("taskbar", "class=${WindowsRegionScenes.TASKBAR_CLASS}"))),
        rect = rect,
        placement = buildJsonObject {
            put("policy", "shell-placed")
            put("promotion", promotion.json())
            put("notification_area", area.json())
            put("reads", reads)
        },
        targetHandle = area.taskbar.handle,
        keyboardCues = false,
        current = { desktop.notifyIcon(uid).rect },
    )
}
