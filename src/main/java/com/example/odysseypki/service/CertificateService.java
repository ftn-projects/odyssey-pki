package com.example.odysseypki.service;

import com.example.odysseypki.acl.AclRepository;
import com.example.odysseypki.certificate.CertificateBuilder;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.entity.Issuer;
import com.example.odysseypki.entity.Subject;
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
import java.util.*;
import java.util.stream.Collectors;

@Component
public class CertificateService {
    private static final Long ROOT_EXPIRATION_MILLIS = 10 * 365 * 24 * 60 * 60 * 1000L; // 10 years
    private static final String KEY_ALGORITHM = "RSA";
    public static final String ROOT_ALIAS = "root";
    public static final String HTTPS_ALIAS = "https-certificate";

    @Autowired
    private AclRepository aclRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    public CertificateBuilder getCertificateBuilder(String parentAlias, Map<String, String> subject)
            throws IOException, GeneralSecurityException {
        var keyPair = generateKeyPair();

        var parent = certificateRepository.findByAlias(parentAlias);
        if (parent.getBasicConstraints() < 0)
            throw new IllegalArgumentException("Parent certificate is not a CA.");

        var parentPrivateKey = aclRepository.load(parentAlias, AclRepository.PRIVATE_KEYS_ACL);
        if (parentPrivateKey == null) return null;

        var issuerName = new X500Name(parent.getSubjectX500Principal().getName());
        var nameArgs = subject.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue()).collect(Collectors.toList());
        var subjectName = new X500Name(String.join(",", nameArgs));

        return new CertificateBuilder(
                new Subject(keyPair.getPublic(), subjectName),
                new Issuer(decodePrivateKey(parentPrivateKey), parent.getPublicKey(), issuerName),
                keyPair.getPrivate(), parentAlias);
    }

    public Certificate save(Certificate certificate) throws IOException, GeneralSecurityException {
        var saved = certificateRepository.save(certificate.getParentAlias(), certificate);
        aclRepository.save(
                certificate.getAlias(),
                encodePrivateKey(certificate.getPrivateKey()),
                AclRepository.PRIVATE_KEYS_ACL
        );
        return saved;
    }

    public void initializeKeyStore() {
        try {
            createRoot();
            getCertificateBuilder(ROOT_ALIAS, Map.of("CN", "Https"))
                    .withAlias(HTTPS_ALIAS)
                    .withExpiration(ROOT_EXPIRATION_MILLIS)
                    .withKeyUsages(List.of(
                            Certificate.KeyUsageValue.DIGITAL_SIGNATURE.name(),
                            Certificate.KeyUsageValue.KEY_ENCIPHERMENT.name(),
                            Certificate.KeyUsageValue.KEY_AGREEMENT.name()))
                    .isHttpsCertificate(true)
                    .build();
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    private void createRoot() throws IOException, GeneralSecurityException, OperatorCreationException {
        var keyPair = generateKeyPair();

        // Self-signed so there is no parent key
        var x500Name = new X500Name("CN=Root");
        var allKeyUsages = Arrays.stream(Certificate.KeyUsageValue.values())
                .map(Certificate.KeyUsageValue::name).toList();

        var certificate = new CertificateBuilder(
                new Subject(keyPair.getPublic(), x500Name),
                new Issuer(keyPair.getPrivate(), keyPair.getPublic(), x500Name),
                keyPair.getPrivate(), null)
                .withAlias(ROOT_ALIAS)
                .withExpiration(ROOT_EXPIRATION_MILLIS)
                .withKeyUsages(allKeyUsages)
                .isRootCertificate(true)
                .build();

        aclRepository.save(ROOT_ALIAS, encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        certificateRepository.saveRoot(certificate);
    }

    public List<X509Certificate> delete(String alias) throws IOException, GeneralSecurityException {
        if (ROOT_ALIAS.equals(alias))
            throw new IllegalArgumentException("Root certificate cannot be deleted");
        return certificateRepository.delete(alias);
    }

    public X509Certificate find(String alias) throws IOException, GeneralSecurityException {
        return certificateRepository.findByAlias(alias);
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

    private static PrivateKey decodePrivateKey(String key) {
        try {
            var keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
            var kf = KeyFactory.getInstance(KEY_ALGORITHM);
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static String encodePrivateKey(PrivateKey key) {
        try {
            var kf = KeyFactory.getInstance(KEY_ALGORITHM);
            var keySpec = kf.getKeySpec(key, PKCS8EncodedKeySpec.class);
            return Base64.getEncoder().encodeToString(keySpec.getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public X509Certificate findByUid(Long uid) {
        return null;
    }
}
