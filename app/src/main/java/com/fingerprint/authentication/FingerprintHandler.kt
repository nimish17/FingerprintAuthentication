package com.fingerprint.authentication

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.app.KeyguardManager
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey


@Suppress("DEPRECATION")
@SuppressLint("NewApi")
class FingerprintHandler(private val context: Context) {

    private lateinit var callback: (code: Int, message: String) -> Unit
    fun initTouchAuth(callback: (code: Int, message: String) -> Unit) {
        this.callback = callback
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (BiometricUtils.isBiometricPromptEnabled && BiometricUtils.isHardwareSupported(context)
                    && BiometricUtils.isPermissionGranted(context)) {
                if (BiometricUtils.isFingerprintAvailable(context)) {
                    val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                    if (keyguardManager.isKeyguardSecure) {
                        generateKey()
                        if (cipherInit()) {
                            val cryptoObject = FingerprintManagerCompat.CryptoObject(cipher!!)
                            startAuth(cryptoObject)
                        }
                    } else callback(201, "Lock screen security disabled in settings")
                } else callback(202, "No fingerprint registered in settings")
            } else @Suppress("DEPRECATION") if (BiometricUtils.isSdkVersionSupported
                    && BiometricUtils.isPermissionGranted(context)) {
                val fingerprintManager = context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
                if (fingerprintManager.isHardwareDetected) {
                    if (fingerprintManager.hasEnrolledFingerprints()) {
                        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                        if (keyguardManager.isKeyguardSecure) {
                            generateKey()
                            if (cipherInit()) {
                                val cryptoObject = FingerprintManager.CryptoObject(cipher!!)
                                startAuth(fingerprintManager, cryptoObject)
                            }
                        } else callback(201, "Lock screen security disabled in settings")
                    } else callback(202, "No fingerprint registered in settings")
                } else callback(203, "Your Device does not have a Fingerprint Sensor")
            }

        } else {
            callback(203, "Your Device does not have a Fingerprint Sensor")
        }
    }

    private var keyStore: KeyStore? = null
    private var cipher: Cipher? = null

    @TargetApi(Build.VERSION_CODES.M)
    private fun generateKey() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore?.load(null)

            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

            keyGenerator.init(KeyGenParameterSpec.Builder("name",
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build())
            keyGenerator.generateKey()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun cipherInit(): Boolean {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get Cipher", e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException("Failed to get Cipher", e)
        }


        try {
            keyStore?.load(null)
            val key = keyStore?.getKey("name", null) as SecretKey
            cipher?.init(Cipher.ENCRYPT_MODE, key)
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return false
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: IOException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        }
    }

    private fun startAuth(cryptoObject: FingerprintManagerCompat.CryptoObject) {
        val cancellationSignal = CancellationSignal()
        val fingerprintManagerCompat = FingerprintManagerCompat.from(context)
        fingerprintManagerCompat.authenticate(cryptoObject, 0, cancellationSignal,
                object : FingerprintManagerCompat.AuthenticationCallback() {
                    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                        super.onAuthenticationError(errMsgId, errString)
                        callback(401, "Fingerprint Authentication error\n$errString")
                    }

                    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                        super.onAuthenticationHelp(helpMsgId, helpString)
                        callback(402, helpString.toString())
                    }

                    override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                        super.onAuthenticationSucceeded(result)
                        callback(200, "Fingerprint Authentication success.")
                    }


                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        callback(400, "Fingerprint Authentication failed.")
                    }
                }, null)
    }

    private fun startAuth(manager: FingerprintManager, cryptoObject: FingerprintManager.CryptoObject) {
        val cancellationSignal = android.os.CancellationSignal()
        manager.authenticate(cryptoObject, cancellationSignal, 0, object : FingerprintManager.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                super.onAuthenticationError(errorCode, errString)
                callback(401, "Fingerprint Authentication error\n$errString")
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                callback(400, "Fingerprint Authentication failed.")
            }

            override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
                super.onAuthenticationSucceeded(result)
                callback(200, "Fingerprint Authentication success.")
            }

            override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence?) {
                super.onAuthenticationHelp(helpCode, helpString)
                callback(402, helpString.toString())
            }
        }, null)
    }

    fun isSuccess(code: Int) = code in 200..299

    fun isEnable(callback: (code: Int, message: String) -> Unit) {
        this.callback = callback
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (BiometricUtils.isBiometricPromptEnabled && BiometricUtils.isHardwareSupported(context)
                    && BiometricUtils.isPermissionGranted(context)) {
                if (BiometricUtils.isFingerprintAvailable(context)) {
                    val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                    if (keyguardManager.isKeyguardSecure) {
                        callback(200, "Yes, you can enable it.")
                    } else callback(405, "Lock screen security not enabled in Settings")
                } else callback(404, "Register at least one fingerprint in Settings")
            } else @Suppress("DEPRECATION") if (BiometricUtils.isSdkVersionSupported
                    && BiometricUtils.isPermissionGranted(context)) {
                val fingerprintManager = context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
                if (fingerprintManager.isHardwareDetected) {
                    if (fingerprintManager.hasEnrolledFingerprints()) {
                        val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                        if (keyguardManager.isKeyguardSecure) {
                            callback(200, "Yes, you can enable it.")
                        } else callback(405, "Lock screen security not enabled in Settings")
                    } else callback(404, "Register at least one fingerprint in Settings")
                } else callback(403, "Your Device does not have a Fingerprint Sensor")
            }
        } else {
            callback(403, "Your Device does not have a Fingerprint Sensor")
        }
    }
}