package com.ciberdefensa.aura

import java.security.GeneralSecurityException
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AuraCryptoSecure private constructor() {
    private external fun decryptModelNative(
        encryptedData: ByteArray,
        keyBytes: ByteArray,
        ivBytes: ByteArray,
    ): ByteArray?

    @Throws(GeneralSecurityException::class)
    private fun decryptWithPlatformCipher(
        encryptedData: ByteArray,
        keyBytes: ByteArray,
        ivBytes: ByteArray,
    ): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                IvParameterSpec(ivBytes),
            )
            return cipher.doFinal(encryptedData)
        } finally {
            Arrays.fill(keyBytes, 0.toByte())
            Arrays.fill(ivBytes, 0.toByte())
        }
    }

    companion object {
        init {
            System.loadLibrary("hev-socks5-tunnel")
        }

        private val instance = AuraCryptoSecure()

        @JvmStatic
        fun decryptModel(
            encryptedData: ByteArray,
            keyBytes: ByteArray,
            ivBytes: ByteArray,
        ): ByteArray {
            try {
                require(
                    encryptedData.isNotEmpty() &&
                        keyBytes.size == 32 &&
                        ivBytes.size == 16,
                ) {
                    "Ciphertext, a 256-bit AES key, and a 16-byte IV are required."
                }
                return requireNotNull(
                    instance.decryptModelNative(encryptedData, keyBytes, ivBytes),
                ) {
                    "Native model decryption failed."
                }
            } finally {
                Arrays.fill(keyBytes, 0.toByte())
                Arrays.fill(ivBytes, 0.toByte())
            }
        }
    }
}
