package com.kardinal.vpncontrol.desktop

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.multi.qrcode.QRCodeMultiReader
import com.google.zxing.qrcode.QRCodeWriter
import com.kardinal.vpncontrol.data.QrExportPolicy
import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import javax.imageio.ImageIO
import javax.imageio.stream.MemoryCacheImageInputStream

/** Client-side, headless image IO. No image path is sent to the controller. */
internal object DesktopQrImage {
    private const val MAX_IMAGE_BYTES = 8 * 1024 * 1024
    private const val MAX_IMAGE_EDGE = 4096

    fun read(path: String): Result<String> = safeResult {
        require(path != "-")
        val bytes = Files.newInputStream(Path.of(path).toAbsolutePath()).use { it.readNBytes(MAX_IMAGE_BYTES + 1) }
        decode(bytes).getOrThrow()
    }

    fun decode(bytes: ByteArray): Result<String> = safeResult {
        require(bytes.size <= MAX_IMAGE_BYTES)
        MemoryCacheImageInputStream(ByteArrayInputStream(bytes)).use { input ->
            val readers = ImageIO.getImageReaders(input)
            require(readers.hasNext())
            val reader = readers.next()
            try {
                reader.input = input
                val width = reader.getWidth(0)
                val height = reader.getHeight(0)
                require(width in 1..MAX_IMAGE_EDGE && height in 1..MAX_IMAGE_EDGE)
                val image = reader.read(0)
                val pixels = image.getRGB(0, 0, width, height, null, 0, width)
                val bitmap = BinaryBitmap(HybridBinarizer(RGBLuminanceSource(width, height, pixels)))
                val results = QRCodeMultiReader().decodeMultiple(bitmap, mapOf(DecodeHintType.TRY_HARDER to true))
                require(results.size == 1)
                results.single().text.also { require(it.isNotEmpty()) }
            } finally {
                reader.dispose()
            }
        }
    }

    fun encode(payload: String): Result<ByteArray> {
        val validated = QrExportPolicy.validate(payload)
        if (validated.isFailure) return Result.failure(IllegalArgumentException(
            if (QrExportPolicy.fits(payload)) "INVALID_ARGUMENT" else "QR_TOO_LARGE"))
        return safeResult {
            val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 768, 768,
                mapOf(EncodeHintType.CHARACTER_SET to "UTF-8", EncodeHintType.MARGIN to 4))
            val image = BufferedImage(matrix.width, matrix.height, BufferedImage.TYPE_INT_RGB)
            for (y in 0 until matrix.height) for (x in 0 until matrix.width) {
                image.setRGB(x, y, if (matrix[x, y]) 0x000000 else 0xFFFFFF)
            }
            ByteArrayOutputStream().use { output ->
                check(ImageIO.write(image, "png", output))
                output.toByteArray()
            }
        }
    }

    private inline fun <T> safeResult(action: () -> T): Result<T> = try {
        Result.success(action())
    } catch (_: Exception) {
        // Image parsers and filesystem failures must not expose input or private paths.
        Result.failure(IllegalArgumentException("INVALID_ARGUMENT"))
    }
}
