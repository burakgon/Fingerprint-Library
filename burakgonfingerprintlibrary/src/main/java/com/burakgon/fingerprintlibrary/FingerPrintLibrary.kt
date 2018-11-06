package com.burakgon.fingerprintlibrary


import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.DialogInterface
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.support.v4.app.ActivityCompat
import android.util.Log
import java.io.IOException
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey


import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException


import java.security.InvalidAlgorithmParameterException

import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.UnrecoverableKeyException

import android.hardware.biometrics.BiometricPrompt
import android.hardware.fingerprint.FingerprintManager
import android.os.CancellationSignal
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat


@RequiresApi(Build.VERSION_CODES.M)
class FingerPrintLibrary(private val appContext: Context, private val listener: onFingerListener) : FingerprintManager.AuthenticationCallback() {

    private var cancellationSignal: CancellationSignal? = null
    private var fingerprintManagerCompat: FingerprintManagerCompat? = null
    private var fingerprintManager: FingerprintManager? = null
    private var keyguardManager: KeyguardManager? = null
    private var keyStore: KeyStore? = null
    private var keyGenerator: KeyGenerator? = null

    private val KEY_NAME = "example_key"

    private val tag = "FingerPrintLibrary"

    private var cipher: Cipher? = null
    private var cryptoObjectManager: FingerprintManager.CryptoObject? = null

    private var biometricPrompt:BiometricPrompt?=null
    private var biocryptoObject: BiometricPrompt.CryptoObject? =  null

    interface onFingerListener
    {
        fun onAuthenticationError(errMsgId: Int, errString: CharSequence)
        fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence)
        fun onAuthenticationFailed()
        fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?)
        fun setTittle() : String
        fun setDescription() : String
        fun setSubtitle() : String
        fun setNegativeButton() : String
    }

    lateinit var myFingerListener : onFingerListener

    init {
        myFingerListener = appContext as onFingerListener

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (getManagers()) {
                generateKey()

                if (cipherInit()) {
                    cipher?.let {
                        cryptoObjectManager = FingerprintManager.CryptoObject(it)
                    }
                }

                if (fingerprintManager != null && cryptoObjectManager != null) {
                    cancellationSignal = CancellationSignal()

                    if (ActivityCompat.checkSelfPermission(appContext, Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED) {
                        fingerprintManager!!.authenticate(cryptoObjectManager, cancellationSignal, 0, this, null)
                    }
                }
            }
        }
        else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P){
            if (getManagers()) {
                generateKey()

                if (cipherInit()) {
                    cipher?.let {
                        biocryptoObject = BiometricPrompt.CryptoObject(it)
                    }
                }

                if (biometricPrompt != null && biocryptoObject != null) {
                    if (ActivityCompat.checkSelfPermission(appContext, Manifest.permission.USE_BIOMETRIC) == PackageManager.PERMISSION_GRANTED) {
                        biometricPrompt!!.authenticate(biocryptoObject, android.os.CancellationSignal(), appContext.mainExecutor,
                            FingerprintCallback(listener)
                        )
                    }
                }
                appContext}
        }
    }


    fun isHardwarePresent(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (fingerprintManager!!.isHardwareDetected == false) {
                return false
            }
            return true
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (fingerprintManagerCompat!!.isHardwareDetected == false) {
                return false
            }
            return true
        }
        return false
    }

    fun isFingerprintRegistered(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (fingerprintManager!!.hasEnrolledFingerprints() == false)
            {
                return false
            }
            return true
        }else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (fingerprintManagerCompat!!.hasEnrolledFingerprints() == false)
            {
                return false
            }
            return true
        }
        return  false
    }

    private fun getManagers(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Build.VERSION.SDK_INT < Build.VERSION_CODES.P ) {

            keyguardManager = appContext.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            fingerprintManager = appContext.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager

            if (fingerprintManager!!.isHardwareDetected == false)
            {
                Log.w(tag,"Cihazda FingerPrint Desteği Yok")
                return false
            }

            if (keyguardManager?.isKeyguardSecure == false) {
                Log.w(tag,"Kilit ekranı güvenliği etkin değil")
                return false
            }

            if (ActivityCompat.checkSelfPermission(appContext,Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                Log.w(tag,"Parmak, kimlik doğrulaması izni etkin değil")
                return false
            }

            if (fingerprintManager?.hasEnrolledFingerprints() == false) {
                Log.w(tag,"Tanımlanmış parmak izi bulunamadı")
                return false
            }
        }
        else  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {

            keyguardManager = appContext.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            fingerprintManagerCompat = FingerprintManagerCompat.from(appContext)

            if (fingerprintManagerCompat!!.isHardwareDetected == false)
            {
                Log.w(tag,"Cihazda FingerPrint Desteği Yok")
                return false
            }

            if (keyguardManager?.isKeyguardSecure == false) {
                Log.w(tag,"Kilit ekranı güvenliği etkin değil")
                return false
            }

            if (ActivityCompat.checkSelfPermission(appContext,Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                Log.w(tag,"Parmak, kimlik doğrulaması izni etkin değil")
                return false
            }

            if (fingerprintManagerCompat?.hasEnrolledFingerprints() == false) {
                Log.w(tag,"Tanımlanmış parmak izi bulunamadı")
                return false
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
            {
                biometricPrompt = BiometricPrompt.Builder(appContext)
                    .setTitle(myFingerListener.setTittle())
                    .setDescription(myFingerListener.setDescription())
                    .setSubtitle(myFingerListener.setSubtitle())
                    .setNegativeButton(myFingerListener.setNegativeButton(), appContext.mainExecutor, DialogInterface.OnClickListener {

                            dialog, which -> listener.onAuthenticationFailed()
                    })
                    .build()
            }
        }
        return true
    }

    private fun generateKey() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                keyStore = KeyStore.getInstance("AndroidKeyStore")
            } catch (e: Exception) {
                e.printStackTrace()
            }

            try {
                keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException("KeyGenerator Örneği Alınamadı", e)
            } catch (e: NoSuchProviderException) {
                throw RuntimeException("KeyGenerator Örneği Alınamadı", e)
            }

            try {
                keyStore?.load(null)
                keyGenerator?.init(
                    KeyGenParameterSpec.Builder(
                        KEY_NAME,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setUserAuthenticationRequired(true)
                        .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7
                        )
                        .build()
                )
                keyGenerator?.generateKey()
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException(e)
            } catch (e: InvalidAlgorithmParameterException) {
                throw RuntimeException(e)
            } catch (e: CertificateException) {
                throw RuntimeException(e)
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
        }

    }

    private fun cipherInit(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                cipher =
                        Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException("Şifre Alınamadı", e)
            } catch (e: NoSuchPaddingException) {
                throw RuntimeException("Şifre Alınamadı", e)
            }

            try {
                keyStore?.load(null)
                val key = keyStore?.getKey(KEY_NAME, null) as SecretKey
                cipher?.init(Cipher.ENCRYPT_MODE, key)
                return true
            } catch (e: KeyPermanentlyInvalidatedException) {
                return false
            } catch (e: KeyStoreException) {
                throw RuntimeException("Şifre Alınamadı", e)
            } catch (e: CertificateException) {
                throw RuntimeException("Şifre Alınamadı", e)
            } catch (e: UnrecoverableKeyException) {
                throw RuntimeException("Şifre Alınamadı", e)
            } catch (e: IOException) {
                throw RuntimeException("Şifre Alınamadı", e)
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException("Şifre Alınamadı", e)
            } catch (e: InvalidKeyException) {
                throw RuntimeException("Şifre Alınamadı", e)
            }
        }
        else
            return false
    }

    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence) {
        myFingerListener.onAuthenticationError(errMsgId, errString)
    }

    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence) {
        myFingerListener.onAuthenticationHelp(helpMsgId, helpString)
    }

    override fun onAuthenticationFailed() {
        myFingerListener.onAuthenticationFailed()
    }

    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
        myFingerListener.onAuthenticationSucceeded(result)
    }
}