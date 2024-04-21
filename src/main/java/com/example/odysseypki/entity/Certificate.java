package com.example.odysseypki.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

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
    private String serialNumber;
    private Date startDate;
    private Date endDate;
    private X509Certificate x509Certificate;

    public boolean isValid() {
        try {
            x509Certificate.checkValidity();
            return true;
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            return false;
        }
    }

    public String getAlias() {
        return x509Certificate.getSerialNumber().toString();
    }

    public enum Extension {
        BASIC_CONSTRAINTS,
        KEY_USAGE,
        SUBJECT_KEY_IDENTIFIER,
        AUTHORITY_KEY_IDENTIFIER
    }

    @Getter
    @AllArgsConstructor
    public enum KeyUsageValue {
        DIGITAL_SIGNATURE("Digital Signature"),
        NON_REPUDIATION("Non-Repudiation"),
        KEY_ENCIPHERMENT("Key Encipherment"),
        DATA_ENCIPHERMENT("Data Encipherment"),
        KEY_AGREEMENT("Key Agreement"),
        CERTIFICATE_SIGN("Certificate Signer"),
        CRL_SIGN("CRL Signer"),
        ENCIPHER_ONLY("Encipher Only"),
        DECIPHER_ONLY("Decipher Only");

        private final String description;
    }
}
