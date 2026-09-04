package com.kardinal.vpncontrol

import android.os.Bundle
import android.view.View
import android.view.WindowManager
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView

class QrCaptureActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isVisualCapture) {
            enforceVisualCaptureFullscreen()
            findViewById<DecoratedBarcodeView>(R.id.zxing_barcode_scanner).visibility = View.INVISIBLE
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && isVisualCapture) enforceVisualCaptureFullscreen()
    }

    private val isVisualCapture: Boolean
        get() = intent.getBooleanExtra(EXTRA_VISUAL_CAPTURE, false)

    @Suppress("DEPRECATION")
    private fun enforceVisualCaptureFullscreen() {
        // SystemUI demo-mode resets between native visual scenes can transiently restore the
        // status bar even though zxing_CaptureTheme is fullscreen. Reassert the production
        // theme's contract after focus changes so the captured scanner viewport is stable.
        window.addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN)
        window.decorView.systemUiVisibility =
            window.decorView.systemUiVisibility or View.SYSTEM_UI_FLAG_FULLSCREEN
    }

    companion object {
        const val EXTRA_VISUAL_CAPTURE = "com.kardinal.vpncontrol.extra.VISUAL_CAPTURE"
    }
}
