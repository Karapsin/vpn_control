package com.kardinal.vpncontrol.desktop

import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import javax.imageio.ImageIO
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Native desktop operations the region capture needs; WindowsRegionDesktop is the only real one. */
internal interface RegionDesktop {
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
    /** Locates a window by native identity and places its visible frame canonically. */
    fun placeWindow(
        sceneId: String,
        role: String,
        rule: TargetRule,
        canonical: CanonicalPlacement,
        move: (Long, PlacementMove, Boolean) -> Unit,
        maxPolls: Int = 80,
    ): LocatedPart {
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
        return LocatedPart(
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
            val layout = stackLayout(parts.map { it.rect.width to it.rect.height })
            val stable = awaitStableFrame(
                sceneId,
                REGION_STABLE_MAX_ATTEMPTS,
                capture = {
                    val frame = desktop.captureScreen(screen)
                    lastFrame = frame
                    val image = composeRegionImage(frame, screen, parts.map { it.rect }, layout)
                    CapturedRegion(frame, image, rgbPixels(image))
                },
                identical = { first, second -> first.pixels.contentEquals(second.pixels) },
                pause = { desktop.pause(REGION_STABLE_INTERVAL_MILLIS) },
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
            writeRefusal(output, sceneId, refusal, lastFrame)
            throw refusal
        }
    }

    private fun placementWithBackdrop(part: LocatedPart): JsonObject = JsonObject(
        part.placement + ("backdrop" to if (part.backdropHandle == null) JsonNull else buildJsonObject {
            put("handle", hexHandle(part.backdropHandle))
            put("rgb", "#%06X".format(WindowsRegionScenes.BACKDROP_RGB))
            put("stacked_below", hexHandle(part.targetHandle))
        }),
    )

    /** Records a refusal raised before [capture] (for example while locating or placing a target). */
    fun recordRefusal(output: Path, refusal: RegionCaptureRefusedException) {
        if (!Files.exists(output.resolve("${refusal.sceneId}.refusal.json"))) writeRefusal(output, refusal.sceneId, refusal, null)
    }

    /** Keeps the frame of the refused moment and the named reason for the reviewer. */
    private fun writeRefusal(output: Path, sceneId: String, refusal: RegionCaptureRefusedException, frame: BufferedImage?) {
        runCatching {
            Files.createDirectories(output)
            val diagnostic = frame ?: desktop.captureScreen(desktop.screen())
            writePng(diagnostic, output.resolve(regionFrameName(sceneId)))
            Files.writeString(
                output.resolve("$sceneId.refusal.json"),
                regionJson.encodeToString(JsonObject.serializer(), buildJsonObject {
                    put("schema_version", REGION_RECORD_SCHEMA)
                    put("scene", sceneId)
                    put("reason", refusal.refusal.reason)
                    put("detail", JsonPrimitive(refusal.detail))
                    put("frame", regionFrameName(sceneId))
                }) + "\n",
            )
        }.exceptionOrNull()?.let(refusal::addSuppressed)
    }

    private fun writePng(image: BufferedImage, path: Path) {
        check(ImageIO.write(image, "png", path.toFile())) { "no PNG writer for $path" }
    }
}
