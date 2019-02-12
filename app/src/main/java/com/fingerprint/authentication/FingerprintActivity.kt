package com.fingerprint.authentication

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_fingerprint.*

class FingerprintActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_fingerprint)
        initTouchAuth()
    }

    private fun initTouchAuth() {
        val handler = FingerprintHandler(this)
        handler.initTouchAuth { code, message ->
            if (handler.isSuccess(code)) {
                Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                startActivity(Intent(this, MainActivity::class.java))
                finish()
            } else {
                errorText.setTextColor(Color.RED)
                errorText.text = message
            }
        }
    }
}