package com.example.odysseypki.service;

import com.example.odysseypki.acl.AclRepository;
import com.example.odysseypki.certificate.CertificateBuilder;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.Console;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Component
public class CertificateService {
    private static final Long ROOT_EXPIRATION_MILLIS = 10 * 365 * 24 * 60 * 60 * 1000L; // 10 years
    private static final String KEY_ALGORITHM = "RSA";
    private static final String ROOT_ALIAS = "root";
    private static final String HTTPS_ALIAS = "https-certificate";

    @Autowired
    private AclRepository aclRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    public Certificate create(
            String parentAlias, String alias,
            String commonName, String email, String uid,
            Date startDate, Date endDate,
            Map<Certificate.Extension, List<String>> extensions)
            throws IOException, GeneralSecurityException, OperatorCreationException {
        return create(
                parentAlias, alias,
                new X500Name("CN=" + commonName + ", E=" + email + ", UID=" + uid),
                startDate, endDate, extensions
        );
    }

    public Certificate create(String parentAlias, String alias, X500Name subjectName,
            Date startDate, Date endDate, Map<Certificate.Extension, List<String>> extensions)
            throws IOException, GeneralSecurityException, OperatorCreationException {
        var keyPair = generateKeyPair();

        var parentPrivateKey = aclRepository.load(parentAlias, AclRepository.PRIVATE_KEYS_ACL);
        if (parentPrivateKey == null) return null;

        var parent = certificateRepository.find(parentAlias);
        var issuerName = new X500Name(parent.getSubjectX500Principal().getName());
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), subjectName)
                .withIssuer(decodePrivateKey(parentPrivateKey), parent.getPublicKey(), issuerName)
                .withStartDate(startDate)
                .withEndDate(endDate)
                .withAlias(alias)
                .withExtensions(extensions)
                .build();

        aclRepository.save(certificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        return certificateRepository.save(parentAlias, certificate);
    }

    public void initializeKeyStore() {
        try {
            createRoot();
            var allKeyUsages = Arrays.stream(Certificate.KeyUsageValue.values()).map(Certificate.KeyUsageValue::name).toList();
            create(ROOT_ALIAS, HTTPS_ALIAS,
                    new X500Name("CN=Https Certificate, OU=Odyssey PKI, O=Odyssey, L=Novi Sad, C=Serbia"),
                    new Date(), new Date(System.currentTimeMillis() + ROOT_EXPIRATION_MILLIS),
                    Map.of(
                            Certificate.Extension.BASIC_CONSTRAINTS, List.of(String.valueOf(true)),
                            Certificate.Extension.KEY_USAGE, allKeyUsages,
                            Certificate.Extension.SUBJECT_KEY_IDENTIFIER, List.of(),
                            Certificate.Extension.AUTHORITY_KEY_IDENTIFIER, List.of())
            );
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    public void createRoot() throws IOException, GeneralSecurityException, OperatorCreationException {
        var keyPair = generateKeyPair();

        // SELF SIGNED SO THERE IS NO PARENT PRIVATE KEY
        var x500Name = new X500Name("CN=Root Certificate, OU=Odyssey PKI, O=Odyssey, L=Novi Sad, C=Serbia");
        var allKeyUsages = Arrays.stream(Certificate.KeyUsageValue.values()).map(Certificate.KeyUsageValue::name).toList();
        var rootCertificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), x500Name)
                .withIssuer(keyPair.getPrivate(), keyPair.getPublic(), x500Name)
                .withExpiration(ROOT_EXPIRATION_MILLIS)
                .withAlias(ROOT_ALIAS)
                .withExtensions(Map.of(
                        Certificate.Extension.BASIC_CONSTRAINTS, List.of(String.valueOf(true)),
                        Certificate.Extension.KEY_USAGE, allKeyUsages,  // ROOT CERTIFICATE CAN PERFORM ALL ACTIONS
                        Certificate.Extension.SUBJECT_KEY_IDENTIFIER, List.of()))
                .build();

        aclRepository.save(rootCertificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        certificateRepository.saveRoot(rootCertificate);
    }

    public List<X509Certificate> delete(String alias) throws IOException, GeneralSecurityException {
        if (ROOT_ALIAS.equals(alias))
            throw new IllegalArgumentException("Root certificate cannot be deleted.");

        return certificateRepository.delete(alias);
    }

    public X509Certificate find(String alias) throws IOException, GeneralSecurityException {
        return certificateRepository.find(alias);
    }

    public List<X509Certificate> findAll() throws IOException, GeneralSecurityException {
        return certificateRepository.findAll();
    }

    public String findParentAlias(String alias) throws IOException {
        return certificateRepository.findParentAlias(alias);
    }

    private static KeyPair generateKeyPair() {
        try {
            var keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            var random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey decodePrivateKey(String key) {
        try {
            var keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
            var kf = KeyFactory.getInstance(KEY_ALGORITHM);
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static String encodePrivateKey(PrivateKey key) {
        try {
            var kf = KeyFactory.getInstance(KEY_ALGORITHM);
            var keySpec = kf.getKeySpec(key, PKCS8EncodedKeySpec.class);
            return Base64.getEncoder().encodeToString(keySpec.getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
