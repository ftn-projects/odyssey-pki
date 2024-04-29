package com.example.odysseypki.certificate;

import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
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
import java.util.stream.Collector;

@NoArgsConstructor
public class CertificateBuilder {
    private Subject subject = null;
    private Issuer issuer = null;
    private Date startDate = null;
    private Date endDate = null;
    private BigInteger serialNumber = null;
    private String alias = null;
    private PrivateKey privateKey = null;
    private Map<Certificate.Extension, List<String>> extensions = new HashMap<>();

    public Certificate build() throws OperatorCreationException, CertificateException, CertIOException {
        // FIELD VALIDATION
        if (subject == null || issuer == null || endDate == null)
            throw new IllegalArgumentException("Missing required fields");
        if (startDate == null) startDate = new Date();
        if (serialNumber == null) serialNumber = generateSerialNumber();
        if (alias == null) alias = serialNumber.toString();
        if (privateKey == null) privateKey = issuer.getPrivateKey();

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
                alias, startDate, endDate,
                privateKey,
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

    public CertificateBuilder withExpiration(long milliseconds) {
        if (startDate == null) startDate = new Date();
        endDate = new Date(startDate.getTime() + milliseconds);
        return this;
    }

    public CertificateBuilder withAlias(String alias) {
        this.alias = alias;
        return this;
    }

    public CertificateBuilder withPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
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
                return;
            case SUBJECT_ALTERNATIVE_NAME:
                var names = new GeneralName[values.size()];
                for (int i = 0; i < values.size(); ++i)
                    names[i] = new GeneralName(GeneralName.dNSName, values.get(i));

                builder.addExtension(Extension.subjectAlternativeName, false,
                    new DERSequence(names));
        }
    }

    private int mapKeyUsage(List<String> values) {
        int keyUsage = 0;
        for (var value : values) {
            switch (Certificate.KeyUsageValue.valueOf(value)) {
                case DIGITAL_SIGNATURE:
                    keyUsage |= KeyUsage.digitalSignature;
                    break;
                case NON_REPUDIATION:
                    keyUsage |= KeyUsage.nonRepudiation;
                    break;
                case KEY_ENCIPHERMENT:
                    keyUsage |= KeyUsage.keyEncipherment;
                    break;
                case DATA_ENCIPHERMENT:
                    keyUsage |= KeyUsage.dataEncipherment;
                    break;
                case KEY_AGREEMENT:
                    keyUsage |= KeyUsage.keyAgreement;
                    break;
                case CERTIFICATE_SIGN:
                    keyUsage |= KeyUsage.keyCertSign;
                    break;
                case CRL_SIGN:
                    keyUsage |= KeyUsage.cRLSign;
                    break;
            }
        }
        return keyUsage;
    }
}
