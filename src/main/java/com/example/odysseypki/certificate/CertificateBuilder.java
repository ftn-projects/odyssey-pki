package com.example.odysseypki.certificate;

import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.*;

@NoArgsConstructor
public class CertificateBuilder {
    private Subject subject = null;
    private Issuer issuer = null;
    private PrivateKey privateKey = null;
    @Getter
    private String parentAlias = null;
    private BigInteger serialNumber = null;
    private Date startDate = null;
    private Date endDate = null;
    private String alias = null;
    private Boolean isHttps = false, isCa = false, isRoot = false;
    private List<String> keyUsages = new ArrayList<>();

    public CertificateBuilder(Subject subject, Issuer issuer, PrivateKey privateKey, String parentAlias) {
        this.subject = subject;
        this.issuer = issuer;
        this.privateKey = privateKey;
        this.parentAlias = parentAlias;
    }

    public Certificate build() throws OperatorCreationException, CertificateException, CertIOException {
        // FIELD VALIDATION
        if (endDate == null)
            throw new IllegalArgumentException("Missing end date or expiration");
        if (isHttps && isCa)
            throw new IllegalArgumentException("HTTPS certificates cannot be CA certificates");
        if (!isHttps) privateKey = issuer.getPrivateKey();
        if (startDate == null) startDate = new Date();
        if (serialNumber == null) serialNumber = generateSerialNumber();
        if (alias == null) alias = serialNumber.toString();

        // BUILDER SETUP
        var builder = new JcaX509v3CertificateBuilder(
                issuer.getX500Name(), serialNumber,
                startDate, endDate,
                subject.getX500Name(),
                subject.getPublicKey());

        addExtensions(builder);

        var signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(issuer.getPrivateKey());
        var x509Certificate = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(builder.build(signer));

        return new Certificate(
                subject, issuer,
                alias, startDate, endDate,
                privateKey, parentAlias,
                x509Certificate
        );
    }

    private BigInteger generateSerialNumber() {
        return BigInteger.valueOf(System.currentTimeMillis());
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

    public CertificateBuilder isHttpsCertificate(boolean b) {
        this.isHttps = b;
        return this;
    }

    public CertificateBuilder isCertificateAuthority(boolean b) {
        this.isCa = b;
        return this;
    }

    public CertificateBuilder isRootCertificate(boolean b) {
        this.isCa = b;
        this.isRoot = b;
        return this;
    }

    public CertificateBuilder withKeyUsages(List<String> keyUsages) {
        this.keyUsages = keyUsages;
        return this;
    }

    private void addExtensions(JcaX509v3CertificateBuilder builder) throws CertIOException {
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(mapKeyUsages()));

        if (!isRoot)
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(issuer.getPublicKey().getEncoded()));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(subject.getPublicKey().getEncoded()));
    }

    private int mapKeyUsages() {
        int encoded = 0;
        for (var usage : keyUsages) {
            var usageValue = Certificate.KeyUsageValue.valueOf(usage);
            switch (usageValue) {
                case DIGITAL_SIGNATURE:
                    encoded |= KeyUsage.digitalSignature;
                    break;
                case NON_REPUDIATION:
                    encoded |= KeyUsage.nonRepudiation;
                    break;
                case KEY_ENCIPHERMENT:
                    if (isCa) throw new InvalidKeyUsageException("CA", usageValue.getDescription());
                    encoded |= KeyUsage.keyEncipherment;
                    break;
                case DATA_ENCIPHERMENT:
                    if (isCa) throw new InvalidKeyUsageException("CA", usageValue.getDescription());
                    encoded |= KeyUsage.dataEncipherment;
                    break;
                case KEY_AGREEMENT:
                    if (isCa) throw new InvalidKeyUsageException("CA", usageValue.getDescription());
                    encoded |= KeyUsage.keyAgreement;
                    break;
                case CERTIFICATE_SIGN:
                    if (!isCa) throw new InvalidKeyUsageException("EE", usageValue.getDescription());
                    encoded |= KeyUsage.keyCertSign;
                    break;
                case CRL_SIGN:
                    if (!isCa) throw new InvalidKeyUsageException("EE", usageValue.getDescription());
                    encoded |= KeyUsage.cRLSign;
                    break;
            }
        }
        return encoded;
    }
}
