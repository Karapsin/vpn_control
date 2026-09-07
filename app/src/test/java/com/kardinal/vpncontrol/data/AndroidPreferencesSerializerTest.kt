package com.kardinal.vpncontrol.data

import androidx.datastore.core.DataStoreFactory
import androidx.datastore.preferences.core.*
import com.kardinal.vpncontrol.model.PersistedState
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import okio.Buffer
import org.junit.Assert.*
import org.junit.Test

class AndroidPreferencesSerializerTest {
    @get:org.junit.Rule val temporary = org.junit.rules.TemporaryFolder()
    private val serializer by lazy { AndroidPreferencesSerializer(temporary.root.toPath()) }

    @Test fun coldLegacyReadSeedsImmutableCacheOnlyAfterCompleteSuccessfulDecode() = runBlocking {
        val value = preferencesOf(stringPreferencesKey("cold") to "persisted")
        val bytes = Buffer().also { PreferencesSerializer.writeTo(value, it) }.readByteArray()
        val first = serializer.readFrom(bytes.inputStream())
        assertSame(first, serializer.readFrom(bytes.inputStream()))
        assertTrue(runCatching { serializer.readFrom(bytes.copyOf(bytes.size - 1).inputStream()) }.isFailure)
        assertSame(first, serializer.readFrom(bytes.inputStream()))
        assertTrue(runCatching { (first as MutablePreferences).putAll() }.isFailure)
    }

    @Test fun completeWireIdentityReusesOnlyFrozenValuesAndRevalidatesEveryByte() = runBlocking {
        val key = stringPreferencesKey("key")
        val frozen = preferencesOf(key to "one").toPreferences()
        val output = ByteArrayOutputStream().also { serializer.writeTo(frozen, it) }.toByteArray()
        assertSame(frozen, serializer.readFrom(output.inputStream()))
        assertTrue(runCatching { (frozen as MutablePreferences).putAll() }.isFailure)
        assertEquals("one", frozen[key])
        val changed = output.copyOf().also { it[it.lastIndex] = 'X'.code.toByte() }
        assertEquals("onX", serializer.readFrom(changed.inputStream())[key])
        assertTrue(runCatching { serializer.readFrom(output.copyOf(output.size - 1).inputStream()) }.isFailure)
        val restored = serializer.readFrom(output.inputStream())
        assertEquals(frozen, restored)
        assertSame(restored, serializer.readFrom(output.inputStream()))
        val mutable = frozen.toMutablePreferences()
        val mutableBytes = ByteArrayOutputStream().also { serializer.writeTo(mutable, it) }.toByteArray()
        assertEquals("one", mutable[key]) // Frozen detection never modifies a mutable caller.
        mutable[key] = "two"
        assertEquals("one", serializer.readFrom(mutableBytes.inputStream())[key])
        assertEquals(0, temporary.root.listFiles()!!.size)
    }

    @Test fun failedPartialWriteCannotPublishCacheAndIndependentStoresNeverShareIt() = runBlocking {
        val key = stringPreferencesKey("key")
        val first = preferencesOf(key to "first").toPreferences()
        val previous = ByteArrayOutputStream().also { serializer.writeTo(first, it) }.toByteArray()
        val second = preferencesOf(key to "other").toPreferences()
        val failedBytes = ByteArrayOutputStream()
        assertTrue(runCatching { serializer.writeTo(second, object : java.io.OutputStream() {
            override fun write(value: Int) { if (failedBytes.size() == 3) throw java.io.IOException("partial") else failedBytes.write(value) }
        }) }.isFailure)
        assertSame(first, serializer.readFrom(previous.inputStream()))
        val other = AndroidPreferencesSerializer(temporary.root.toPath())
        val different = async(Dispatchers.Default) { other.readFrom(previous.inputStream()) }
        assertEquals(first, different.await())
        assertNotSame(first, different.await())
        assertTrue(runCatching { serializer.readFrom(failedBytes.toByteArray().inputStream()) }.isFailure)
    }

    @Test fun clearedWeakValueFallsBackToStockDecode() = runBlocking {
        val value = preferencesOf(stringPreferencesKey("key") to "value").toPreferences()
        val output = ByteArrayOutputStream().also { serializer.writeTo(value, it) }.toByteArray()
        val field = AndroidPreferencesSerializer::class.java.getDeclaredField("cached").apply { isAccessible = true }
        val cache = field.get(serializer)
        val reference = cache.javaClass.getDeclaredField("value").apply { isAccessible = true }.get(cache) as java.lang.ref.WeakReference<*>
        reference.clear()
        val decoded = serializer.readFrom(output.inputStream())
        assertEquals(value, decoded)
        assertNotSame(value, decoded)
    }
    @Test fun exactWireBytesAndReadCompatibilityForEveryType() = runBlocking {
        val values = preferencesOf(booleanPreferencesKey("bool") to true, intPreferencesKey("int") to -17,
            longPreferencesKey("long") to Long.MIN_VALUE, floatPreferencesKey("float") to -0.5f,
            doublePreferencesKey("double") to Double.POSITIVE_INFINITY, stringPreferencesKey("東京") to "one\n東京😀\u0000",
            stringSetPreferencesKey("set") to linkedSetOf("two", "one", "東京"), byteArrayPreferencesKey("bytes") to byteArrayOf(0, -1, 2))
        for (prefs in listOf(emptyPreferences(), values, preferencesOf(stringPreferencesKey("malformed") to "\uD800x\uDC00"))) {
            val original = Buffer().also { PreferencesSerializer.writeTo(prefs, it) }.readByteArray()
            val output = ByteArrayOutputStream().also { serializer.writeTo(prefs, it) }.toByteArray()
            assertArrayEquals(original, output)
            val expected = PreferencesSerializer.readFrom(Buffer().write(original))
            assertEquals(expected, serializer.readFrom(ByteArrayInputStream(output)))
            assertEquals(expected, serializer.readFrom(ByteArrayInputStream(original)))
        }
        assertEquals(PreferencesSerializer.defaultValue, serializer.defaultValue)
    }

    @Test fun boundedReaderMatchesStockForDuplicateMapsAndLargeUnknownFields() = runBlocking {
        val key = stringPreferencesKey("duplicate")
        suspend fun wire(value: String) = Buffer().also { PreferencesSerializer.writeTo(preferencesOf(key to value), it) }.readByteArray()
        val unknown = ByteArray(70_000) { (it and 127).toByte() }
        val document = ByteArrayOutputStream().also { output ->
            output.write(wire("first")); output.write(wire("last"))
            output.write(byteArrayOf(0x4a, 0xf0.toByte(), 0xa2.toByte(), 0x04)) // field 9, length 70,000
            output.write(unknown)
            output.write(byteArrayOf(0x13, 0x18, 0x01, 0x14)) // unknown group with one scalar field
        }.toByteArray()
        val expected = PreferencesSerializer.readFrom(Buffer().write(document))
        assertEquals(expected, serializer.readFrom(document.inputStream()))
        assertEquals("last", serializer.readFrom(document.inputStream())[key])
    }

    @Test fun boundedReaderMatchesStockForMapEntryWithoutKey() = runBlocking {
        assertBoundedMatchesStock(entry(value(stringValue("value-without-key"))))
    }

    @Test fun boundedReaderMatchesStockForMapEntryWithoutValue() = runBlocking {
        assertBoundedMatchesStock(entry(keyField("key-without-value")))
    }

    @Test fun boundedReaderMatchesStockForKnownFieldWithWrongWireType() = runBlocking {
        assertBoundedMatchesStock(entry(keyField("wrong-wire") + value(byteArrayOf(0x2d, 1, 0, 0, 0))))
    }

    @Test fun boundedReaderMatchesStockForInvalidUtf8StringPayload() = runBlocking {
        assertBoundedMatchesStock(entry(keyField("invalid-utf8") + value(lengthField(5, byteArrayOf(0xc3.toByte(), 0x28)))))
    }

    @Test fun boundedReaderMatchesStockForTagVarintBeyondThirtyTwoBits() = runBlocking {
        // AndroidX readRawVarint32 truncates the tag before extracting field/wire.
        assertBoundedMatchesStock(hex("8a80808010080a016b12032a0176"))
    }

    @Test fun boundedReaderMatchesStockForLengthVarintBeyondThirtyTwoBits() = runBlocking {
        // AndroidX readRawVarint32 truncates the entry length to eight bytes.
        assertBoundedMatchesStock(hex("0a88808080100a016b12032a0176"))
    }

    @Test fun boundedReaderMatchesStockForMalformedUtf8MapKey() = runBlocking {
        // Map keys use protobuf's strict readStringRequireUtf8, unlike values.
        assertBoundedMatchesStock(hex("0a080a01ff12032a0176"))
    }

    @Test fun boundedReaderMatchesStockForMalformedUtf8LargeMapKey() = runBlocking {
        val key = ByteArray(65_537) { 'a'.code.toByte() }.also { it[it.lastIndex] = 0xff.toByte() }
        assertBoundedMatchesStock(entry(lengthField(1, key) + value(stringValue("v"))))
    }

    @Test fun boundedReaderMatchesStockForMismatchedUnknownGroupEnd() = runBlocking {
        assertBoundedMatchesStock(byteArrayOf(0x13, 0x1c))
    }

    @Test fun boundedReaderMatchesStockForRepeatedStringSetOneof() = runBlocking {
        val setOne = lengthField(1, "one".toByteArray())
        val setTwo = lengthField(1, "two".toByteArray())
        assertBoundedMatchesStock(entry(keyField("set") + value(lengthField(6, setOne) + lengthField(6, setTwo))))
    }

    private suspend fun assertBoundedMatchesStock(document: ByteArray) {
        val stock = runCatching { PreferencesSerializer.readFrom(Buffer().write(document)) }
        val bounded = runCatching { serializer.readFrom(document.inputStream()) }
        assertEquals(stock.exceptionOrNull()?.javaClass, bounded.exceptionOrNull()?.javaClass)
        if (stock.isSuccess) assertEquals(stock.getOrThrow(), bounded.getOrThrow())
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun varint(value: Int): ByteArray {
        var remaining = value
        val result = ByteArrayOutputStream()
        while (remaining and -128 != 0) {
            result.write((remaining and 127) or 128)
            remaining = remaining ushr 7
        }
        result.write(remaining)
        return result.toByteArray()
    }

    private fun lengthField(number: Int, payload: ByteArray): ByteArray = ByteArrayOutputStream().also {
        it.write((number shl 3) or 2)
        it.write(varint(payload.size))
        it.write(payload)
    }.toByteArray()

    private fun entry(payload: ByteArray) = lengthField(1, payload)
    private fun keyField(value: String) = lengthField(1, value.toByteArray())
    private fun stringValue(value: String) = lengthField(5, value.toByteArray())
    private fun value(payload: ByteArray) = lengthField(2, payload)

    @Test fun chunkBoundariesDefaultsAndRawNumericBitsMatchStockProtobuf() = runBlocking {
        val boundary = "x".repeat(65_535) + "😀\uD800東京\u0000\n"
        val values = preferencesOf(
            stringPreferencesKey("") to "",
            booleanPreferencesKey("false") to false,
            intPreferencesKey("minimum") to Int.MIN_VALUE,
            intPreferencesKey("zero") to 0,
            longPreferencesKey("maximum") to Long.MAX_VALUE,
            floatPreferencesKey("float-negative-zero") to -0.0f,
            floatPreferencesKey("float-nan") to java.lang.Float.intBitsToFloat(0x7fc01234),
            doublePreferencesKey("double-nan") to java.lang.Double.longBitsToDouble(0x7ff8000000001234L),
            stringPreferencesKey(boundary) to boundary.repeat(3),
            stringSetPreferencesKey("empty-set") to emptySet(),
            stringSetPreferencesKey("mixed-set") to linkedSetOf("", boundary, "\uDC00", "😀"),
            byteArrayPreferencesKey("empty-bytes") to byteArrayOf(),
            byteArrayPreferencesKey("large-bytes") to ByteArray(170_000) { it.toByte() },
        )
        val stock = Buffer().also { PreferencesSerializer.writeTo(values, it) }.readByteArray()
        var largestWrite = 0
        val sink = ByteArrayOutputStream()
        serializer.writeTo(values, object : java.io.OutputStream() {
            override fun write(value: Int) { sink.write(value) }
            override fun write(bytes: ByteArray, offset: Int, count: Int) {
                largestWrite = maxOf(largestWrite, count)
                sink.write(bytes, offset, count)
            }
        })
        assertTrue(largestWrite in 1..65_536)
        assertArrayEquals(stock, sink.toByteArray())
        assertEquals(PreferencesSerializer.readFrom(Buffer().write(stock)), serializer.readFrom(sink.toByteArray().inputStream()))
    }

    @Test fun mutableCallerChangesDuringOutputCannotChangeTheCapturedDocumentOrSeedCache() = runBlocking {
        val text = stringPreferencesKey("text")
        val bytes = byteArrayPreferencesKey("bytes")
        val strings = stringSetPreferencesKey("set")
        val values = mutablePreferencesOf(text to "before", bytes to byteArrayOf(1, 2, 3), strings to setOf("one", "two"))
        val before = values.toPreferences()
        val stock = Buffer().also { PreferencesSerializer.writeTo(before, it) }.readByteArray()
        val sink = ByteArrayOutputStream()
        serializer.writeTo(values, object : java.io.OutputStream() {
            override fun write(value: Int) { error("bounded byte-array writes required") }
            override fun write(buffer: ByteArray, offset: Int, count: Int) {
                values[text] = "after"
                values[bytes] = byteArrayOf(9)
                values[strings] = setOf("changed")
                values[stringPreferencesKey("new")] = "new"
                sink.write(buffer, offset, count)
            }
        })
        assertArrayEquals(stock, sink.toByteArray())
        assertEquals(before, serializer.readFrom(sink.toByteArray().inputStream()))
        assertEquals("after", values[text])
    }

    @Test fun legacyFileNoOpAndNewCommitRemainImmutableAndReadableByStockSerializer() = runBlocking {
        val directory = java.nio.file.Files.createTempDirectory("preferences-wire-").toFile()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val key = stringPreferencesKey("app_mode")
            val file = File(directory, "vpn_control.preferences_pb")
            val legacy = Buffer().also { PreferencesSerializer.writeTo(preferencesOf(key to "VPN"), it) }.readByteArray()
            file.writeBytes(legacy)
            val store = DataStoreFactory.create(serializer = serializer, scope = scope) { file }
            val owner = AndroidConfigurationStore(store, { PersistedState(appMode =
                com.kardinal.vpncontrol.model.AppMode.valueOf(it[key] ?: "VPN")) }, "owner")
            assertEquals("VPN", store.data.first()[key])
            val result = owner.edit("owner", 0) { it[key] = "PROXY_ONLY" }
            assertEquals(1L, result.revision)
            assertEquals(1L, owner.edit("owner", 1) { it[key] = "PROXY_ONLY" }.revision)
            val committed = store.data.first()
            assertTrue(runCatching { (committed as MutablePreferences)[key] = "de" }.isFailure)
            assertEquals(committed, PreferencesSerializer.readFrom(Buffer().write(file.readBytes())))
        } finally { scope.coroutineContext[Job]!!.cancelAndJoin(); directory.deleteRecursively() }
    }

    @Test fun corruptInputAndWriteFailureKeepOriginalFailureSemantics() = runBlocking {
        val bytes = byteArrayOf(-1, -1, -1)
        val old = runCatching { PreferencesSerializer.readFrom(Buffer().write(bytes)) }.exceptionOrNull()
        val fresh = runCatching { serializer.readFrom(ByteArrayInputStream(bytes)) }.exceptionOrNull()
        assertNotNull(old)
        assertEquals(old!!::class, fresh!!::class)
        val failure = java.io.IOException("fixture")
        assertSame(failure, runCatching {
            serializer.writeTo(preferencesOf(stringPreferencesKey("key") to "value"),
                object : java.io.OutputStream() { override fun write(value: Int) { throw failure } })
        }.exceptionOrNull())
    }
}
