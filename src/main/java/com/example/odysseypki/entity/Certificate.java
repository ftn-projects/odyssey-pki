package com.example.odysseypki.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

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
        DigitalSignature,
        IntermediateCA,
        EndEntity,
        Https
    }

    public boolean isValid() {
        try {
            x509Certificate.checkValidity();
            x509Certificate.getCriticalExtensionOIDs();
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
