package com.example.odysseypki.certificate;

import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@NoArgsConstructor
public class CertificateBuilder {
    private Subject subject = null;
    private Issuer issuer = null;
    private Date startDate = null;
    private Date endDate = null;
    private BigInteger serialNumber = null;
    private final List<Extension> extensions = new ArrayList<>();

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

        for (var e : extensions)
            builder.addExtension(e);

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

    public CertificateBuilder withExtension() {
        extensions.add(null); // TODO FIGURE IT OUT
        return this;
    }
}
