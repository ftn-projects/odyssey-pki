package com.example.odysseypki.certificate;

import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Component
public class CertificateGenerator {
    public CertificateGenerator() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate generateCertificate(X500Name subject, PublicKey subjectPublicKey,
                                                       X500Name issuer, PrivateKey issuerPrivateKey,
                                                       Date startDate, Date endDate, String serialNumber) {
        try {
            var signerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            signerBuilder.setProvider("BC");

            var contentSigner = signerBuilder.build(issuerPrivateKey);
            var certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, new BigInteger(serialNumber), startDate, endDate, subject, subjectPublicKey
            );

            // TODO EXTENSIONS
//            // Adding Basic Constraints to indicate this is not a CA certificate
//            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
//                    new org.bouncycastle.asn1.x509.BasicConstraints(false));
//            // Adding Key Usage extension
//            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
//                    new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature |
//                            org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment));
//            // Adding Authority Key Identifier
//            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
//                    new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(issuer.getEncoded()));

            var certHolder = certBuilder.build(contentSigner);
            var certConverter = new JcaX509CertificateConverter();
            certConverter.setProvider("BC");
            return certConverter.getCertificate(certHolder);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
