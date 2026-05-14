package com.kardinal.vpncontrol.desktop

import java.awt.Dimension
import java.awt.image.BufferedImage
import javax.imageio.ImageIO
import kotlin.math.roundToInt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

private const val TinyInspectableTrayIconSize = 4

class DesktopTrayImageConfigTest {
    @Test
    fun linuxAddsXEmbedPaintGuardWithoutAwtAutosize() {
        val config = desktopTrayImageConfig(
            trayIconSize = Dimension(24, 24),
            osName = "Linux",
        )

        assertEquals(28, config.imageSize)
        assertFalse(config.autoSize)
        assertTrue(config.preferFixedResource)
    }

    @Test
    fun linuxUsesLargerHostDimensionBecauseXEmbedCanUnderreportPanelSize() {
        val config = desktopTrayImageConfig(
            trayIconSize = Dimension(24, 16),
            osName = "Linux",
        )

        assertEquals(28, config.imageSize)
        assertFalse(config.autoSize)
        assertTrue(config.preferFixedResource)
    }

    @Test
    fun linuxTraySizeFallsBackOnlyWhenHostSizeIsMissing() {
        assertEquals(
            28,
            desktopTrayImageConfig(
                trayIconSize = Dimension(0, 0),
                osName = "Linux",
            ).imageSize,
        )
        assertEquals(
            128,
            desktopTrayImageConfig(
                trayIconSize = Dimension(256, 256),
                osName = "Linux",
            ).imageSize,
        )
    }

    @Test
    fun nonLinuxKeepsAdaptiveTraySizeAndAutosize() {
        val config = desktopTrayImageConfig(
            trayIconSize = Dimension(40, 32),
            osName = "Windows 11",
        )

        assertEquals(40, config.imageSize)
        assertTrue(config.autoSize)
        assertFalse(config.preferFixedResource)
    }

    @Test
    fun adaptiveTraySizeKeepsExistingBounds() {
        assertEquals(
            22,
            desktopTrayImageConfig(
                trayIconSize = Dimension(12, 16),
                osName = "Mac OS X",
            ).imageSize,
        )
        assertEquals(
            128,
            desktopTrayImageConfig(
                trayIconSize = Dimension(256, 256),
                osName = "Mac OS X",
            ).imageSize,
        )
    }

    @Test
    fun linuxTrayResourceIsFixedSize() {
        val image = loadLinuxTrayResource()

        assertEquals(24, image.width)
        assertEquals(24, image.height)
    }

    @Test
    fun linuxTrayResourceKeepsBlueShieldArtwork() {
        val image = loadLinuxTrayResource()
        var brightPixels = 0
        for (y in 0 until image.height) {
            for (x in 0 until image.width) {
                if (isBrightShieldPixel(image.getRGB(x, y))) {
                    brightPixels += 1
                }
            }
        }

        val totalPixels = image.width * image.height
        val brightRatio = brightPixels.toDouble() / totalPixels
        assertFalse(image.colorModel.hasAlpha())
        assertTrue(isBlueIconBackground(image.getRGB(0, 0)))
        assertTrue(isBlueIconBackground(image.getRGB(image.width - 1, 0)))
        assertTrue(isBlueIconBackground(image.getRGB(0, image.height - 1)))
        assertTrue(isBlueIconBackground(image.getRGB(image.width - 1, image.height - 1)))
        assertTrue(brightRatio in 0.08..0.18, "Bright pixel ratio was $brightRatio")
    }

    @Test
    fun linuxTrayRendererMatchesHostSizeAndProtectsBlueEdges() {
        val source = loadLinuxTrayResource()

        (8..128).forEach { size ->
            val image = renderLinuxTrayImage(source, size)

            assertEquals(size, image.width, "Rendered width for $size px tray")
            assertEquals(size, image.height, "Rendered height for $size px tray")
            assertFalse(image.colorModel.hasAlpha(), "Linux tray image must be opaque at $size px")
            assertBlueProtectedEdges(image)
            assertNoBrightPixelsInGuardBand(image, size)
            if (size >= TinyInspectableTrayIconSize) {
                assertTrue(
                    countCenterContentPixels(image) > 0,
                    "Expected non-background center content at $size px",
                )
                assertTrue(
                    countPixels(image, ::isBrightShieldPixel) > 0,
                    "Expected bright shield/check pixels at $size px",
                )
            }
        }
    }

    @Test
    fun linuxTrayRendererKeepsShieldReadableAtPolybarSize() {
        val image = renderLinuxTrayImage(loadLinuxTrayResource(), 28)
        val brightBounds = brightPixelBounds(image)

        assertTrue(
            brightBounds.first >= 12,
            "Expected rendered shield to be at least 12 px wide, but was ${brightBounds.first}",
        )
        assertTrue(
            brightBounds.second >= 14,
            "Expected rendered shield to be at least 14 px tall, but was ${brightBounds.second}",
        )
    }

    @Test
    fun tinyLinuxTrayRendererUsesSimplifiedOpaqueGlyph() {
        val image = renderLinuxTrayImage(loadLinuxTrayResource(), 8)

        assertEquals(8, image.width)
        assertEquals(8, image.height)
        assertFalse(image.colorModel.hasAlpha())
        assertBlueProtectedEdges(image)
        assertNoBrightPixelsInGuardBand(image, 8)
        assertTrue(countPixels(image, ::isBrightShieldPixel) > 0)
    }

    private fun loadLinuxTrayResource(): BufferedImage {
        val stream = javaClass.classLoader.getResourceAsStream("tray_icon_linux.png")
        return assertNotNull(stream).use { resource -> ImageIO.read(resource) }
    }

    private fun assertBlueProtectedEdges(image: BufferedImage) {
        val last = image.width - 1
        for (position in 0..last) {
            assertBlueProtectedEdge(image.getRGB(position, 0), position, 0)
            assertBlueProtectedEdge(image.getRGB(position, last), position, last)
            assertBlueProtectedEdge(image.getRGB(0, position), 0, position)
            assertBlueProtectedEdge(image.getRGB(last, position), last, position)
        }
    }

    private fun assertBlueProtectedEdge(rgb: Int, x: Int, y: Int) {
        assertTrue(
            isBlueIconBackground(rgb),
            "Expected protected blue tray edge at ($x, $y), but was ${rgbHex(rgb)}",
        )
        assertFalse(
            isBrightShieldPixel(rgb),
            "Expected non-bright tray edge at ($x, $y), but was ${rgbHex(rgb)}",
        )
    }

    private fun assertNoBrightPixelsInGuardBand(image: BufferedImage, size: Int) {
        val guard = maxOf(1, (size * 0.18).roundToInt())
        val last = image.width - 1
        for (y in 0 until image.height) {
            for (x in 0 until image.width) {
                if (x < guard || y < guard || x > last - guard || y > last - guard) {
                    assertFalse(
                        isBrightShieldPixel(image.getRGB(x, y)),
                        "Expected no bright pixels in $guard px guard band at ($x, $y) for $size px tray",
                    )
                }
            }
        }
    }

    private fun countCenterContentPixels(image: BufferedImage): Int {
        val background = image.getRGB(0, 0)
        val start = image.width / 4
        val end = image.width - start
        var count = 0
        for (y in start until end) {
            for (x in start until end) {
                if (!isCloseToColor(image.getRGB(x, y), background)) {
                    count += 1
                }
            }
        }
        return count
    }

    private fun countPixels(image: BufferedImage, predicate: (Int) -> Boolean): Int {
        var count = 0
        for (y in 0 until image.height) {
            for (x in 0 until image.width) {
                if (predicate(image.getRGB(x, y))) count += 1
            }
        }
        return count
    }

    private fun brightPixelBounds(image: BufferedImage): Pair<Int, Int> {
        var minX = image.width
        var minY = image.height
        var maxX = -1
        var maxY = -1
        for (y in 0 until image.height) {
            for (x in 0 until image.width) {
                if (isBrightShieldPixel(image.getRGB(x, y))) {
                    minX = minOf(minX, x)
                    minY = minOf(minY, y)
                    maxX = maxOf(maxX, x)
                    maxY = maxOf(maxY, y)
                }
            }
        }
        assertTrue(maxX >= minX && maxY >= minY, "Expected rendered shield pixels")
        return Pair(maxX - minX + 1, maxY - minY + 1)
    }

    private fun isBrightShieldPixel(rgb: Int): Boolean {
        val red = rgb shr 16 and 0xff
        val green = rgb shr 8 and 0xff
        val blue = rgb and 0xff
        return red >= 200 && green >= 200 && blue >= 200
    }

    private fun isBlueIconBackground(rgb: Int): Boolean {
        val red = rgb shr 16 and 0xff
        val green = rgb shr 8 and 0xff
        val blue = rgb and 0xff
        return red <= 20 && green in 70..95 && blue >= 180
    }

    private fun isCloseToColor(rgb: Int, color: Int): Boolean {
        val tolerance = 18
        return kotlin.math.abs((rgb shr 16 and 0xff) - (color shr 16 and 0xff)) <= tolerance &&
            kotlin.math.abs((rgb shr 8 and 0xff) - (color shr 8 and 0xff)) <= tolerance &&
            kotlin.math.abs((rgb and 0xff) - (color and 0xff)) <= tolerance
    }

    private fun rgbHex(rgb: Int): String {
        return "#%06x".format(rgb and 0xffffff)
    }
}
