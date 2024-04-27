package com.example.odysseypki.certificate;

public class InvalidKeyUsageException extends RuntimeException {
    public InvalidKeyUsageException(String type, String usage) {
        super(type + " certificates should not have \"" + usage + "\" key usage");
    }
}
