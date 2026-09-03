package com.kardinal.vpncontrol

import android.os.Bundle
import android.view.View
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView

class QrCaptureActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.getBooleanExtra(EXTRA_VISUAL_CAPTURE, false)) {
            findViewById<DecoratedBarcodeView>(R.id.zxing_barcode_scanner).visibility = View.INVISIBLE
        }
    }

    companion object {
        const val EXTRA_VISUAL_CAPTURE = "com.kardinal.vpncontrol.extra.VISUAL_CAPTURE"
    }
}
