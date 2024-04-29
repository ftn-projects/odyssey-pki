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

    @Getter
    @AllArgsConstructor
    public enum KeyUsageValue {
        DIGITAL_SIGNATURE("Digital Signature"),
        NON_REPUDIATION("Non-Repudiation"),
        KEY_ENCIPHERMENT("Key Encipherment"),
        DATA_ENCIPHERMENT("Data Encipherment"),
        KEY_AGREEMENT("Key Agreement"),
        CERTIFICATE_SIGN("Certificate Signer"),
        CRL_SIGN("CRL Signer");

        private final String description;
    }
}
