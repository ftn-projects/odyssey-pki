package com.example.odysseypki.algorithm;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AesEncryption {
    private static final String ALGORITHM = "AES";
    private static final Integer KEY_SIZE = 32;

    private static SecretKey getSecretKey(String secret) throws NoSuchAlgorithmException {
        var sha = MessageDigest.getInstance("SHA-256");

        var hashedKey = sha.digest(secret.getBytes());
        var keyBytes = new byte[KEY_SIZE];
        System.arraycopy(hashedKey, 0, keyBytes, 0, KEY_SIZE);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    public static String encrypt(String data, String secret) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        var cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(secret));

        var encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedData, String secret) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        var cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(secret));

        var decoded = Base64.getDecoder().decode(encryptedData);
        var decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }
}