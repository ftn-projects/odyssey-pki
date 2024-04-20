package com.example.odysseypki.service;

import com.example.odysseypki.certificate.CertificateGenerator;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
import com.example.odysseypki.repository.AclRepository;
import com.example.odysseypki.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

@Component
public class CertificateService {
    @Autowired
    private AclRepository aclRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    public Certificate add(String parentAlias, String commonName, String email, String uid, Date startDate, Date endDate) throws IllegalBlockSizeException,
            NoSuchPaddingException, IOException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, ClassNotFoundException {
        KeyPair keyPairSubject = generateKeyPair();
        if (keyPairSubject == null) return null;
        Subject subject = new Subject(keyPairSubject.getPublic(), getX500Name(commonName, email, uid));

        var parent = certificateRepository.load(parentAlias);
        Issuer issuer = new Issuer(getPrivateKey(aclRepository.load(parentAlias, AclRepository.PK_ACL)), parent.getPublicKey(), new X500Name(parent.getIssuerX500Principal().getName()));

        var serialNumber = BigInteger.valueOf(System.currentTimeMillis()).toString();
        var x509certificate =  CertificateGenerator.generateCertificate(subject, issuer, startDate, endDate, serialNumber);
        var certificate = new Certificate(subject, issuer,serialNumber, startDate, endDate, x509certificate);

        aclRepository.save(certificate.getAlias(), Arrays.toString(keyPairSubject.getPrivate().getEncoded()), AclRepository.PK_ACL);
        certificateRepository.save(parentAlias, certificate);
        return certificate;
    }
    public void delete(String alias) throws IOException, ClassNotFoundException {
        certificateRepository.delete(alias);
    }
    public X509Certificate get(String alias){
        return certificateRepository.load(alias);
    }
    public void getAll(){}

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static X500Name getX500Name(String commonName, String email, String uid) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, commonName);
        builder.addRDN(BCStyle.E, email);
        builder.addRDN(BCStyle.UID, uid);
        return builder.build();
    }

    public static PrivateKey getPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte [] pkcs8EncodedBytes = Base64.decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

}
