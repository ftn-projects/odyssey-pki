package com.example.odysseypki.certificate;

import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.*;

@NoArgsConstructor
public class CertificateBuilder {
    private Subject subject = null;
    private Issuer issuer = null;
    private Date startDate = null;
    private Date endDate = null;
    private BigInteger serialNumber = null;
    private Map<Certificate.Extension, List<String>> extensions = new HashMap<>();

    public Certificate build() throws OperatorCreationException, CertificateException, CertIOException {
        // FIELD VALIDATION
        if (subject == null || issuer == null || endDate == null)
            throw new IllegalArgumentException("Missing required fields");
        if (startDate == null) startDate = new Date();
        if (serialNumber == null) serialNumber = generateSerialNumber();

        // BUILDER SETUP
        var builder = new JcaX509v3CertificateBuilder(
                issuer.getX500Name(), serialNumber,
                startDate, endDate,
                subject.getX500Name(),
                subject.getPublicKey());

        // ADDING EXTENSIONS
        for (var entry : extensions.entrySet())
            buildExtension(builder, entry.getKey(), entry.getValue());

        var signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(issuer.getPrivateKey());
        var x509Certificate = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(builder.build(signer));

        return new Certificate(
                subject, issuer,
                serialNumber.toString(),
                startDate, endDate,
                x509Certificate
        );
    }

    private BigInteger generateSerialNumber() {
        return BigInteger.valueOf(System.currentTimeMillis());
    }

    public CertificateBuilder withSubject(PublicKey key, X500Name x500Name) {
        subject = new Subject(key, x500Name);
        return this;
    }

    public CertificateBuilder withSubject(PublicKey key, String commonName, String email, String uid) {
        return withSubject(key, new X500Name("CN=" + commonName + ", E=" + email + ", UID=" + uid));
    }

    public CertificateBuilder withIssuer(PrivateKey privateKey, PublicKey publicKey, X500Name x500Name) {
        issuer = new Issuer(privateKey, publicKey, x500Name);
        return this;
    }

    public CertificateBuilder withStartDate(Date startDate) {
        this.startDate = startDate;
        return this;
    }

    public CertificateBuilder withEndDate(Date endDate) {
        this.endDate = endDate;
        return this;
    }

    public CertificateBuilder withExpiration(int years) {
        if (startDate == null) startDate = new Date();
        endDate = new Date(startDate.getTime() + years * 31556952000L);
        return this;
    }

    public CertificateBuilder withSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    public CertificateBuilder withExtensions(Map<Certificate.Extension, List<String>> extensions) {
        this.extensions = extensions;
        return this;
    }

    private void buildExtension(JcaX509v3CertificateBuilder builder, Certificate.Extension extension, List<String> values) throws CertIOException {
        switch (extension) {
            case BASIC_CONSTRAINTS:
                builder.addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(values.get(0).equalsIgnoreCase("true")));
                return;
            case KEY_USAGE:
                builder.addExtension(Extension.keyUsage, true,
                        new KeyUsage(mapKeyUsage(values)));
                return;
            case SUBJECT_KEY_IDENTIFIER:
                builder.addExtension(Extension.subjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(subject.getPublicKey().getEncoded()));
                return;
            case AUTHORITY_KEY_IDENTIFIER:
                builder.addExtension(Extension.authorityKeyIdentifier, false,
                        new AuthorityKeyIdentifier(issuer.getPublicKey().getEncoded()));
        }
    }

    private int mapKeyUsage(List<String> values) {
        int keyUsage = 0;
        for (var value : values) {
            switch (value) {
                case "Digital Signature":
                    keyUsage |= KeyUsage.digitalSignature;
                    break;
                case "Non-Repudiation":
                    keyUsage |= KeyUsage.nonRepudiation;
                    break;
                case "Key Encipherment":
                    keyUsage |= KeyUsage.keyEncipherment;
                    break;
                case "Data Encipherment":
                    keyUsage |= KeyUsage.dataEncipherment;
                    break;
                case "Key Agreement":
                    keyUsage |= KeyUsage.keyAgreement;
                    break;
                case "Key Cert Sign":
                    keyUsage |= KeyUsage.keyCertSign;
                    break;
                case "CRL Sign":
                    keyUsage |= KeyUsage.cRLSign;
                    break;
                case "Encipher Only":
                    keyUsage |= KeyUsage.encipherOnly;
                    break;
                case "Decipher Only":
                    keyUsage |= KeyUsage.decipherOnly;
                    break;
            }
        }
        return keyUsage;
    }
}
