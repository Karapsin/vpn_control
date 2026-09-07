package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import java.io.Writer
import java.util.UUID
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** A single frontend export capability, fully prepared privately before the system file picker. */
internal class AndroidRoutingExportControl(
    private val controllerId: String,
    private val read: suspend (ControlRequest) -> AndroidControlDocumentResponse,
    private val inputSpool: () -> AndroidControlInputSpool,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) : AutoCloseable {
    data class Prepared(val result: ControlResult, val fileName: String? = null)
    private class Pending(val result: ControlResult, val name: String, val input: AndroidControlInputSpool)
    private var pending: Pending? = null
    private var preparing = false
    private var generation = 0L
    private var outputClaimed = false

    suspend fun prepare(): Prepared {
        pending?.let { return Prepared(it.result, it.name) }
        if (preparing) return Prepared(failure(ControlCode.BUSY))
        preparing = true
        val current = generation
        val request = ControlRequest(UUID.randomUUID().toString(), ControlCommand(ControlOperationId.ROUTING_EXPORT),
            controllerId = controllerId)
        var input: AndroidControlInputSpool? = null
        try {
            val response = withContext(io) {
                read(request).also { response ->
                    if (response.result.code == ControlCode.OK && response.result.final &&
                        response.result.controllerId == controllerId && response.result.requestId == request.requestId) {
                        val spool = inputSpool().also { input = it }
                        check(response.writeExportContentTo(spool))
                        spool.seal()
                    }
                }
            }
            if (current != generation) return Prepared(failure(ControlCode.CANCELLED, request.requestId))
            if (response.result.code != ControlCode.OK || !response.result.final) return Prepared(response.result)
            if (input == null) return Prepared(failure(ControlCode.OUTCOME_UNKNOWN, request.requestId))
            val name = "vpn-control-routing-rules-${java.time.Instant.now().toString().replace(':', '-')}.json"
            val ready = Pending(response.result, name, requireNotNull(input))
            pending = ready
            outputClaimed = false
            input = null
            return Prepared(ready.result, ready.name)
        } catch (_: OutOfMemoryError) {
            return Prepared(failure(ControlCode.RUNTIME_FAILED, request.requestId, "RESOURCE_EXHAUSTED"))
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            return Prepared(failure(ControlCode.UNAVAILABLE, request.requestId))
        } finally {
            try { input?.close() }
            catch (_: Exception) { }
            catch (_: OutOfMemoryError) { }
            finally { preparing = false }
        }
    }

    /** The writer is for a fresh CreateDocument result; external output is never reopened for retry. */
    suspend fun write(openWriter: () -> Writer, discardFailedDestination: () -> Boolean): ControlResult {
        val selected = pending
        if (selected == null) {
            // A restored system picker can create its document after this frontend's
            // private input was lost. Retire that exact fresh URI, without exporting
            // replacement-owner settings. A delivered output is claimed only once.
            if (outputClaimed) return failure(ControlCode.CONFLICT)
            outputClaimed = true
            val removed = try {
                withContext(kotlinx.coroutines.NonCancellable + io) { discardFailedDestination() }
            } catch (_: Exception) { false }
            catch (_: OutOfMemoryError) { false }
            return failure(ControlCode.CONFLICT, warning = if (removed) null else "EXPORT_OUTPUT_CLEANUP_UNAVAILABLE")
        }
        outputClaimed = true
        pending = null
        var attemptedOutput = false
        var completedOutput = false
        var result = selected.result
        try {
            withContext(io) {
                attemptedOutput = true
                openWriter().use { writer ->
                    val source = selected.input.source()
                    val buffer = CharArray(32768)
                    try {
                        var count = 0
                        while (true) {
                            val unit = source.read()
                            if (unit < 0) break
                            buffer[count++] = unit.toChar()
                            if (count == buffer.size) { writer.write(buffer, 0, count); buffer.fill('\u0000'); count = 0 }
                        }
                        if (count != 0) writer.write(buffer, 0, count)
                    } finally { buffer.fill('\u0000') }
                }
                completedOutput = true
            }
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            // A cancelled reader/write must not leave its newly created document.
            // Prompt cancellation after a successful close preserves known bytes.
            if (attemptedOutput && !completedOutput) {
                try { withContext(kotlinx.coroutines.NonCancellable + io) { discardFailedDestination() } }
                catch (_: Exception) { }
                catch (_: OutOfMemoryError) { }
            }
            throw cancelled
        } catch (error: Throwable) {
            if (error !is Exception && error !is OutOfMemoryError) throw error
            val removed = !attemptedOutput || try { withContext(io) { discardFailedDestination() } } catch (_: Exception) { false }
            result = selected.result.copy(code = ControlCode.PERSISTENCE_FAILED,
                warnings = (if (error is OutOfMemoryError) listOf("RESOURCE_EXHAUSTED") else emptyList()) +
                    if (removed) emptyList() else listOf("EXPORT_OUTPUT_CLEANUP_UNAVAILABLE"))
        } finally {
            try { selected.input.close() }
            catch (_: Exception) { result = result.copy(warnings = result.warnings + "PRIVATE_INPUT_CLEANUP_UNAVAILABLE") }
            catch (_: OutOfMemoryError) { result = result.copy(warnings = result.warnings + "PRIVATE_INPUT_CLEANUP_UNAVAILABLE") }
        }
        return result
    }

    override fun close() {
        generation++
        val retired = pending
        pending = null
        try { retired?.input?.close() }
        catch (_: Exception) { }
        catch (_: OutOfMemoryError) { }
    }
    private fun failure(code: ControlCode, requestId: String = UUID.randomUUID().toString(), warning: String? = null) =
        ControlResult(controllerId, requestId, code, 0, warnings = listOfNotNull(warning))
}
