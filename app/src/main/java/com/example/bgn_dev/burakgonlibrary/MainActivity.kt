package com.example.bgn_dev.burakgonlibrary

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.hardware.biometrics.BiometricPrompt

import android.hardware.fingerprint.FingerprintManager

import android.widget.Toast
import android.os.Build
import com.burakgon.fingerprintlibrary.FingerPrintLibrary
import com.burakgon.fingerprintlibrary.FingerPrintLibrary.onFingerListener

class MainActivity : AppCompatActivity(), onFingerListener  {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
        {
            // val : immutable / Read Only
            // var : mutable / Read and Write

            val flt  = FingerPrintLibrary(this, this)
            if (flt.isHardwarePresent() == false)
            {
                Toast.makeText(this, "Cihazda FingerPrint Desteği Yok", Toast.LENGTH_LONG).show()
            }
            else if (flt.isFingerprintRegistered() == false)
            {
                Toast.makeText(this, "Tanımlanmış parmak izi bulunamadı", Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence) {
        Toast.makeText(this, "Kimlik Doğrulama Hatası\n" + errString,Toast.LENGTH_SHORT).show()
    }

    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence) {
        Toast.makeText(this,"Kimlik Doğrulama Yardım\n" + helpString,Toast.LENGTH_SHORT).show()
    }

    override fun onAuthenticationFailed() {
        Toast.makeText(this,"Kimlik Doğrulama Başarısız",Toast.LENGTH_SHORT).show()
    }

    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
        Toast.makeText(this,"Kimlik Doğrulama Başarılı",Toast.LENGTH_SHORT).show()
    }

    override fun setTittle(): String {
        return "Parmak İzi"
    }

    override fun setDescription(): String {
        return "Lütfen parmağınızı parmak izi sensörüne yerleştirin."
    }

    override fun setSubtitle(): String {
        return "setSubtitle Test"
    }

    override fun setNegativeButton(): String {
        return "İptal"
    }
}
