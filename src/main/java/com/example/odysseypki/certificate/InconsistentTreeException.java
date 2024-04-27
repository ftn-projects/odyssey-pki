package com.example.odysseypki.certificate;

public class InconsistentTreeException extends RuntimeException {
    public InconsistentTreeException(String alias) {
        super("Inconsistent tree state: alias \"" + alias + "\" not found in the KeyStore");
    }
}
