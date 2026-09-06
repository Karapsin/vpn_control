package com.kardinal.vpncontrol.desktop

import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopQrImageTest {
    @Test fun unicodePayloadRoundTripsWithoutAWindowOrDisplay() {
        for (payload in listOf("socks://127.0.0.1:1080#東京 😀", "é".repeat(800), "😀".repeat(400))) {
            val bytes = DesktopQrImage.encode(payload).getOrThrow()
            assertContentEquals(bytes, DesktopQrImage.encode(payload).getOrThrow())
            assertEquals(payload, DesktopQrImage.decode(bytes).getOrThrow())
        }
        assertEquals("QR_TOO_LARGE", DesktopQrImage.encode("é".repeat(801)).exceptionOrNull()?.message)
    }

    @Test fun corruptOversizedAndAmbiguousImagesFailWithoutPrivateDetails() {
        assertEquals("INVALID_ARGUMENT", DesktopQrImage.decode("private text".toByteArray()).exceptionOrNull()?.message)
        assertTrue(DesktopQrImage.decode(ByteArray(8 * 1024 * 1024 + 1)).isFailure)
        fun png(image: BufferedImage) = ByteArrayOutputStream().use {
            ImageIO.write(image, "png", it)
            it.toByteArray()
        }
        assertTrue(DesktopQrImage.decode(png(BufferedImage(4097, 1, BufferedImage.TYPE_INT_RGB))).isFailure)
        val combined = BufferedImage(1536, 768, BufferedImage.TYPE_INT_RGB)
        val graphics = combined.createGraphics()
        try {
            for ((index, payload) in listOf("first", "second").withIndex()) {
                val image = ImageIO.read(DesktopQrImage.encode(payload).getOrThrow().inputStream())
                graphics.drawImage(image, index * 768, 0, null)
            }
        } finally { graphics.dispose() }
        assertTrue(DesktopQrImage.decode(png(combined)).isFailure)
        assertEquals("INVALID_ARGUMENT", DesktopQrImage.read("missing private path").exceptionOrNull()?.message)
    }
}
