package com.burakgon.fingerprintlibrary



import android.annotation.TargetApi
import android.hardware.biometrics.BiometricPrompt
import android.os.Build

@TargetApi(Build.VERSION_CODES.P)
class FingerprintCallback(private val listener: FingerPrintLibrary.onFingerListener) : BiometricPrompt.AuthenticationCallback()
{
    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        listener.onAuthenticationError(errorCode, errString.toString())
        super.onAuthenticationError(errorCode, errString)
    }

    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
        listener.onAuthenticationSucceeded(null)
        super.onAuthenticationSucceeded(result)
    }

    override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
        listener.onAuthenticationHelp(helpCode, helpString.toString())
        super.onAuthenticationHelp(helpCode, helpString)
    }

    override fun onAuthenticationFailed() {
        listener.onAuthenticationFailed()
        super.onAuthenticationFailed()
    }
}