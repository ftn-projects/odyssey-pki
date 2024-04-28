package com.example.odysseypki.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
public class Certificate {
    private Subject subject;
    private Issuer issuer;
    private String alias;
    private Date startDate;
    private Date endDate;
    private PrivateKey privateKey;
    private X509Certificate x509Certificate;

    public boolean isValid() {
        try {
            x509Certificate.checkValidity();
            return true;
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            return false;
        }
    }

    public enum Extension {
        BASIC_CONSTRAINTS, // da li je CA => true/false
        KEY_USAGE, // iz enuma ispod
        SUBJECT_KEY_IDENTIFIER, // automatic na backu
        AUTHORITY_KEY_IDENTIFIER, // automatic na backu
        SUBJECT_ALTERNATIVE_NAME // automatic na backu
    }

    @Getter
    @AllArgsConstructor
    public enum KeyUsageValue { // https => non CA
        DIGITAL_SIGNATURE("Digital Signature"), // uvek
        NON_REPUDIATION("Non-Repudiation"), // uvek
        KEY_ENCIPHERMENT("Key Encipherment"), // non CA
        DATA_ENCIPHERMENT("Data Encipherment"), // non CA
        KEY_AGREEMENT("Key Agreement"), // non CA
        CERTIFICATE_SIGN("Certificate Signer"), // CA
        CRL_SIGN("CRL Signer"), // CA
        ENCIPHER_ONLY("Encipher Only"), // izbacujemo
        DECIPHER_ONLY("Decipher Only"); // izbacujemo

        private final String description;
    }
}
