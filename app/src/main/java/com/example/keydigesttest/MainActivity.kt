package com.example.keydigesttest

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.widget.TextView
import java.lang.IllegalStateException
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException


class MainActivity : AppCompatActivity() {

    companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val KEY_ALIAS = "DummyECKey123"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val textView = findViewById<TextView>(R.id.textView)

        findViewById<Button>(R.id.key_button)?.setOnClickListener {
            var success = false
            try {
                val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
                val builder = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_NONE)
                gen.initialize(builder.build(), SecureRandom())
                val keyPair = gen.generateKeyPair()
                success = true
            } catch (e: IllegalStateException) {
            } catch (e: NoSuchAlgorithmException) {
            } catch (e: NoSuchProviderException) {
            } catch (e: InvalidAlgorithmParameterException) {
            } catch (e: SecurityException) {
            }
            textView.text = if (success) "Key generated" else "Failed to generate key"
        }

        findViewById<Button>(R.id.digest_button)?.setOnClickListener {
            var info = ""
            try {
                val keyStore = KeyStore.getInstance(PROVIDER)
                keyStore.load(null)
                (keyStore.getKey(KEY_ALIAS, null) as? PrivateKey)?.let { key ->
                    val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
                    keyFactory.getKeySpec(key, KeyInfo::class.java)?.let { keyInfo ->
                        val sb = StringBuilder("Digests = {")
                        val digests = keyInfo.digests
                        digests.forEachIndexed { index, name ->
                            sb.append(name)
                            if (index != digests.lastIndex) sb.append(", ")
                        }
                        sb.append("}")
                        info = sb.toString()
                    }
                }
            } catch (e: KeyStoreException) {
            } catch (e: NoSuchProviderException) {
            } catch (e: InvalidKeySpecException) {
            }
            textView.text = if (info.isNotEmpty()) info else "Failed to enumerate key digests"
        }
    }
}
