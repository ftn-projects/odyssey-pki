package com.example.odysseypki.controller;

import com.example.odysseypki.dto.CertificateDTO;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class ExtensionMapper {

    public static List<CertificateDTO.Extension> readExtensions(X509Certificate certificate) throws CertificateEncodingException {
        var extensions = new ArrayList<CertificateDTO.Extension>();
        var holder = new JcaX509CertificateHolder(certificate);

        // Basic Constraints
        var bcExt = holder.getExtension(Extension.basicConstraints);
        if (bcExt != null) {
            var bc = BasicConstraints.getInstance(bcExt.getParsedValue());
            extensions.add(new CertificateDTO.Extension(
                    "Basic Constraints",
                    bcExt.isCritical(),
                    List.of(String.valueOf(bc.isCA()))));
        }

        // Key Usage
        var kuExt = holder.getExtension(Extension.keyUsage);
        if (kuExt != null) {
            var ku = KeyUsage.getInstance(kuExt.getParsedValue());
            extensions.add(new CertificateDTO.Extension(
                    "Key Usage",
                    kuExt.isCritical(),
                    mapKeyUsageValues(ku)));
        }

        // Subject Key Identifier
        var skiExt = holder.getExtension(Extension.subjectKeyIdentifier);
        if (skiExt != null) {
            var ski = SubjectKeyIdentifier.getInstance(skiExt.getParsedValue());
            extensions.add(new CertificateDTO.Extension(
                    "Subject Key Identifier",
                    skiExt.isCritical(),
                    List.of(ski.getKeyIdentifier())));
        }

        // Authority Key Identifier
        var akiExt = holder.getExtension(Extension.authorityKeyIdentifier);
        if (akiExt != null) {
            var aki = AuthorityKeyIdentifier.getInstance(akiExt.getParsedValue());
            extensions.add(new CertificateDTO.Extension(
                    "Authority Key Identifier",
                    akiExt.isCritical(),
                    List.of(aki.getKeyIdentifier())));
        }

        return extensions;
    }

    private static List<Object> mapKeyUsageValues(KeyUsage ku) {
        var values = new ArrayList<>();
        if (ku.hasUsages(KeyUsage.digitalSignature)) values.add("Digital Signature");
        if (ku.hasUsages(KeyUsage.nonRepudiation)) values.add("Non-Repudiation");
        if (ku.hasUsages(KeyUsage.keyEncipherment)) values.add("Key Encipherment");
        if (ku.hasUsages(KeyUsage.dataEncipherment)) values.add("Data Encipherment");
        if (ku.hasUsages(KeyUsage.keyAgreement)) values.add("Key Agreement");
        if (ku.hasUsages(KeyUsage.keyCertSign)) values.add("Key Cert Sign");
        if (ku.hasUsages(KeyUsage.cRLSign)) values.add("CRL Sign");
        if (ku.hasUsages(KeyUsage.encipherOnly)) values.add("Encipher Only");
        if (ku.hasUsages(KeyUsage.decipherOnly)) values.add("Decipher Only");
        return values;
    }
}