package com.example.odysseypki.service;

import com.example.odysseypki.certificate.CertificateBuilder;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.acl.AclRepository;
import com.example.odysseypki.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Component
public class CertificateService {
    @Autowired
    private AclRepository aclRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    public Certificate create(String parentAlias, String commonName, String email, String uid, Date startDate, Date endDate) throws GeneralSecurityException,
            IOException, OperatorCreationException, ClassNotFoundException {
        var keyPair = generateKeyPair();
        if (keyPair == null) return null;

        var parentPrivateKey = aclRepository.load(parentAlias, AclRepository.PRIVATE_KEYS_ACL_PATH);
        if (parentPrivateKey == null) return null;

        var parent = certificateRepository.find(parentAlias);
        var issuerName = new X500Name(parent.getIssuerX500Principal().getName());
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), commonName, email, uid)
                .withIssuer(decodePrivateKey(parentPrivateKey), parent.getPublicKey(), issuerName)
                .withStartDate(startDate)
                .withEndDate(endDate)
                .build();

        aclRepository.save(certificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL_PATH);
        return certificateRepository.save(parentAlias, certificate);
    }

    public Certificate createRoot() throws IOException, GeneralSecurityException, OperatorCreationException {
        var keyPair = generateKeyPair();
        if (keyPair == null) return null;

        // SELF SIGNED SO THERE IS NOT PARENT PRIVATE KEY
        var x500Name = new X500Name("CN=root");
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), x500Name)
                .withIssuer(keyPair.getPrivate(), keyPair.getPublic(), x500Name)
                .withExpiration(10)
                .build();

        aclRepository.save(certificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL_PATH);
        return certificateRepository.saveRoot(certificate);
    }

    public List<X509Certificate> delete(String alias) throws IOException, ClassNotFoundException, GeneralSecurityException {
        return certificateRepository.delete(alias);
    }

    public X509Certificate find(String alias) throws GeneralSecurityException, IOException {
        return certificateRepository.find(alias);
    }

    public List<X509Certificate> findAll() throws GeneralSecurityException, IOException, ClassNotFoundException {
        return certificateRepository.findAll();
    }

    public String getRootAlias() throws IOException, ClassNotFoundException {
        return certificateRepository.getRootAlias();
    }

    private static KeyPair generateKeyPair() {
        try {
            var keyGen = KeyPairGenerator.getInstance("RSA");
            var random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey decodePrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        var keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
        var kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    public static String encodePrivateKey(PrivateKey key) throws GeneralSecurityException {
        var kf = KeyFactory.getInstance("RSA");
        var keySpec = kf.getKeySpec(key, PKCS8EncodedKeySpec.class);
        return Base64.getEncoder().encodeToString(keySpec.getEncoded());
    }
}
