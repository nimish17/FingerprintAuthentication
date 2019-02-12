# FingerprintAuthentication

1) Use FingerprintHandler & BiometricUtils class for biometric authentication

2) Add below permissions in your AndroidMenifest.xml

    **<uses-permission android:name="android.permission.USE_BIOMETRIC" />
    <uses-permission android:name="android.permission.USE_FINGERPRINT" />**

3) Use this code for start authentication

        val handler = FingerprintHandler(this)
        handler.initTouchAuth { code, message ->
            if (handler.isSuccess(code)) {
                Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                /* Open next screen from here */
                finish()
            } else {
                errorText.setTextColor(Color.RED)
                errorText.text = message
            }
        }
