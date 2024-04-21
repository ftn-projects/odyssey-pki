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

    public enum Extension {
        BASIC_CONSTRAINTS,
        KEY_USAGE,
        SUBJECT_KEY_IDENTIFIER,
        AUTHORITY_KEY_IDENTIFIER
    }

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

    @Override
    public String toString() {
        return "Certificate{" +
                "issuer='" + issuer + '\'' +
                ", subject='" + subject + '\'' +
                ", startDate=" + startDate +
                ", endDate=" + endDate +
                '}';
    }
}
