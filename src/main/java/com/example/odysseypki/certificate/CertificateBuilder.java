package com.example.odysseypki.certificate;

import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import lombok.NoArgsConstructor;
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

@NoArgsConstructor
public class CertificateBuilder {
    private Subject subject = null;
    private Issuer issuer = null;
    private Date startDate = null, endDate = null;
    private BigInteger serialNumber = null;
    private String alias = null;
    private PrivateKey privateKey = null;
    private Boolean isRoot = false, isCa = false, isHttps = false;
    private final List<String> keyUsages = new ArrayList<>(), altNames = new ArrayList<>();

    public Certificate build() throws OperatorCreationException, CertificateException, CertIOException {
        // FIELD VALIDATION
        if (subject == null || issuer == null || endDate == null)
            throw new IllegalArgumentException("Missing required fields");
        if (startDate == null) startDate = new Date();
        if (serialNumber == null) serialNumber = generateSerialNumber();
        if (alias == null) alias = serialNumber.toString();
        if (!isHttps) privateKey = issuer.getPrivateKey();

        // BUILDER SETUP
        var builder = new JcaX509v3CertificateBuilder(
                issuer.getX500Name(), serialNumber,
                startDate, endDate,
                subject.getX500Name(),
                subject.getPublicKey());

        // ADDING EXTENSIONS
        buildExtensions(builder);

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

    public CertificateBuilder setRootCertificate(Boolean b) {
        this.isRoot = b;
        this.isCa = b;
        return this;
    }

    public CertificateBuilder setCaCertificate(boolean b) {
        this.isCa = b;
        return this;
    }

    public CertificateBuilder setHttpsCertificate(Boolean b) {
        this.isHttps = b;
        return this;
    }

    public CertificateBuilder withKeyUsages(List<String> keyUsages) {
        this.keyUsages.addAll(keyUsages);
        return this;
    }

    public CertificateBuilder withAltNames(List<String> altNames) {
        this.altNames.addAll(altNames);
        return this;
    }

    private void buildExtensions(JcaX509v3CertificateBuilder builder) throws CertIOException {
        builder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(isCa));

        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(mapKeyUsage(keyUsages)));

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(subject.getPublicKey().getEncoded()));

        if (!isRoot)
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(issuer.getPublicKey().getEncoded()));

        var names = new GeneralName[altNames.size()];
        var flag = isHttps ? GeneralName.dNSName : GeneralName.rfc822Name;
        for (int i = 0; i < altNames.size(); ++i)
            names[i] = new GeneralName(flag, altNames.get(i));
        if (names.length > 0)
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new DERSequence(names));
    }

    private int mapKeyUsage(List<String> values) {
        int keyUsage = 0;
        for (var value : values) {
            switch (Certificate.KeyUsageValue.valueOf(value)) {
                case DIGITAL_SIGNATURE:
                    keyUsage |= KeyUsage.digitalSignature;
                    break;
                case NON_REPUDIATION:
                    if (isHttps)
                        throw new IllegalArgumentException("Non-repudiation is not allowed for HTTPS certificates");
                    keyUsage |= KeyUsage.nonRepudiation;
                    break;
                case KEY_ENCIPHERMENT:
                    if (isCa)
                        throw new IllegalArgumentException("Key encipherment is not allowed for CA certificates");
                    keyUsage |= KeyUsage.keyEncipherment;
                    break;
                case DATA_ENCIPHERMENT:
                    if (isCa || isHttps)
                        throw new IllegalArgumentException("Data encipherment is not allowed for CA or HTTPS certificates");
                    keyUsage |= KeyUsage.dataEncipherment;
                    break;
                case KEY_AGREEMENT:
                    if (isCa)
                        throw new IllegalArgumentException("Key agreement is not allowed for CA certificates");
                    keyUsage |= KeyUsage.keyAgreement;
                    break;
                case CERTIFICATE_SIGN:
                    if (!isCa)
                        throw new IllegalArgumentException("Certificate signing is only allowed for CA certificates");
                    keyUsage |= KeyUsage.keyCertSign;
                    break;
                case CRL_SIGN:
                    if (!isCa)
                        throw new IllegalArgumentException("CRL signing is only allowed for CA certificates");
                    keyUsage |= KeyUsage.cRLSign;
                    break;
            }
        }
        return keyUsage;
    }
}
