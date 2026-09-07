package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.ControlResult

/** Transport-only streaming content; never exposed as a fake empty public result. */
internal class AndroidControlDocumentResponse(val result: ControlResult,
    private val content: ((Appendable) -> Unit)? = null) {
    fun writeTo(output: Appendable) {
        if (content == null) ControlDocumentCodec.writeResult(result, output)
        else ControlDocumentCodec.writeResultWithContent(result, output, content)
    }
    /** GUI/file adapters receive the same captured raw export as the document transport. */
    fun writeExportContentTo(output: Appendable): Boolean {
        val export = content ?: return false
        export(output)
        return true
    }
    override fun toString() = "AndroidControlDocumentResponse(<redacted>)"
}
