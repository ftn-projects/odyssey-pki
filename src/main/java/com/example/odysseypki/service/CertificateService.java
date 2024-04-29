package com.example.odysseypki.service;

import com.example.odysseypki.acl.AclRepository;
import com.example.odysseypki.certificate.CertificateBuilder;
import com.example.odysseypki.dto.CertificateCreationDTO;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.repository.CertificateRepository;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Component
public class CertificateService {
    private static final Long ROOT_EXPIRATION_MILLIS = 10 * 365 * 24 * 60 * 60 * 1000L; // 10 years
    private static final String KEY_ALGORITHM = "RSA";
    public static final String ROOT_ALIAS = "root";
    public static final String MIDDLE_ALIAS = "middle";
    public static final String HTTPS_ALIAS = "https-certificate";

    @Autowired
    private AclRepository aclRepository;
    @Autowired
    private CertificateRepository certificateRepository;


    public Certificate createCaCertificate(CertificateCreationDTO dto) throws GeneralSecurityException, IOException, OperatorCreationException {
        var parentAlias = dto.getParentAlias();
        var commonName = dto.getCommonName();
        var startDate = new Date(dto.getStartDate());
        var endDate = new Date(dto.getEndDate());
        var isHttpsCertificate = dto.getIsHttps();
        var keyUsages = dto.getKeyUsages();

        var parent = certificateRepository.find(parentAlias);
        if (parent == null)
            throw new IllegalArgumentException("Parent certificate with provided alias does not exist.");

        if (parent.getBasicConstraints() < 0)
            throw new IllegalArgumentException("Parent certificate is not a CA.");

        var parentPrivateKey = aclRepository.load(parentAlias, AclRepository.PRIVATE_KEYS_ACL);
        if (parentPrivateKey == null) return null;

        var keyPair = generateKeyPair();

        var subjectName = Map.of("CN", commonName);
        var issuerName = X500NameFormatter.format(parent.getSubjectX500Principal());
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), X500NameFormatter.format(subjectName))
                .withIssuer(decodePrivateKey(parentPrivateKey), parent.getPublicKey(), issuerName)
                .withStartDate(startDate)
                .withEndDate(endDate)
                .withPrivateKey(isHttpsCertificate ? keyPair.getPrivate() : null)
                .setCaCertificate(true)
                .withKeyUsages(keyUsages)
                .build();

        aclRepository.save(certificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        return certificateRepository.save(parentAlias, certificate);
    }

    public Certificate createHttpsCertificate(CertificateCreationDTO dto) throws GeneralSecurityException, IOException, OperatorCreationException {
        var parentAlias = dto.getParentAlias();
        var commonName = dto.getCommonName();
        var startDate = new Date(dto.getStartDate());
        var endDate = new Date(dto.getEndDate());
        var isHttpsCertificate = dto.getIsHttps();
        var keyUsages = dto.getKeyUsages();

        var parent = certificateRepository.find(parentAlias);
        if (parent == null)
            throw new IllegalArgumentException("Parent certificate with provided alias does not exist.");

        if (parent.getBasicConstraints() < 0)
            throw new IllegalArgumentException("Parent certificate is not a CA.");

        var parentPrivateKey = aclRepository.load(parentAlias, AclRepository.PRIVATE_KEYS_ACL);
        if (parentPrivateKey == null) return null;

        var keyPair = generateKeyPair();

        var subjectName = Map.of("CN", commonName);
        var issuerName = X500NameFormatter.format(parent.getSubjectX500Principal());
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), X500NameFormatter.format(subjectName))
                .withIssuer(decodePrivateKey(parentPrivateKey), parent.getPublicKey(), issuerName)
                .withStartDate(startDate)
                .withEndDate(endDate)
                .withPrivateKey(isHttpsCertificate ? keyPair.getPrivate() : null)
                .setHttpsCertificate(true)
                .withKeyUsages(keyUsages)
                .withAltNames(List.of("localhost", "*localhost"))
                .build();

        aclRepository.save(certificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        return certificateRepository.save(parentAlias, certificate);
    }

    public Certificate createEndEntityCertificate(CertificateCreationDTO dto) throws GeneralSecurityException, IOException, OperatorCreationException {
        var parentAlias = dto.getParentAlias();
        var commonName = dto.getCommonName();
        var uid = dto.getUid();
        var startDate = new Date(dto.getStartDate());
        var endDate = new Date(dto.getEndDate());
        var keyUsages = dto.getKeyUsages();
        var email = dto.getEmail();

        var parent = certificateRepository.find(parentAlias);
        if (parent == null)
            throw new IllegalArgumentException("Parent certificate with provided alias does not exist.");

        if (parent.getBasicConstraints() < 0)
            throw new IllegalArgumentException("Parent certificate is not a CA.");

        var parentPrivateKey = aclRepository.load(parentAlias, AclRepository.PRIVATE_KEYS_ACL);
        if (parentPrivateKey == null) return null;

        var keyPair = generateKeyPair();

        var subjectName = Map.of("CN", commonName, "UID", uid);
        var issuerName = X500NameFormatter.format(parent.getSubjectX500Principal());
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), X500NameFormatter.format(subjectName))
                .withIssuer(decodePrivateKey(parentPrivateKey), parent.getPublicKey(), issuerName)
                .withStartDate(startDate)
                .withEndDate(endDate)
                .withPrivateKey(keyPair.getPrivate())
                .withKeyUsages(keyUsages)
                .withAltNames(List.of(email))
                .build();

        aclRepository.save(certificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        return certificateRepository.save(parentAlias, certificate);
    }

    public Certificate create(String parentAlias, String alias, String subjectName, Date startDate, Date endDate, Boolean isCa, Boolean isHttps, List<String> keyUsages, List<String> altNames) throws GeneralSecurityException, IOException, OperatorCreationException {
        var parent = certificateRepository.find(parentAlias);
        if (parent == null)
            throw new IllegalArgumentException("Parent certificate with provided alias does not exist.");

        if (parent.getBasicConstraints() < 0)
            throw new IllegalArgumentException("Parent certificate is not a CA.");

        var parentPrivateKey = aclRepository.load(parentAlias, AclRepository.PRIVATE_KEYS_ACL);
        if (parentPrivateKey == null) return null;

        var keyPair = generateKeyPair();

        var issuerName = X500NameFormatter.format(parent.getSubjectX500Principal());
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), X500NameFormatter.format(subjectName))
                .withIssuer(decodePrivateKey(parentPrivateKey), parent.getPublicKey(), issuerName)
                .withStartDate(startDate)
                .withEndDate(endDate)
                .withAlias(alias)
                .withPrivateKey(keyPair.getPrivate())
                .setCaCertificate(isCa)
                .setHttpsCertificate(isHttps)
                .withKeyUsages(keyUsages)
                .withAltNames(altNames)
                .build();

        aclRepository.save(certificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        return certificateRepository.save(parentAlias, certificate);
    }

    public void initializeKeyStore() {
        try {
            createRoot();
            create(ROOT_ALIAS, MIDDLE_ALIAS,
                    "CN=Odyssey PKI Middle, O=Odyssey, OU=Odyssey PKI, L=Novi Sad, C=Serbia",
                    new Date(), new Date(System.currentTimeMillis() + ROOT_EXPIRATION_MILLIS),
                    true, false, List.of(
                            Certificate.KeyUsageValue.DIGITAL_SIGNATURE.name(),
                            Certificate.KeyUsageValue.NON_REPUDIATION.name(),
                            Certificate.KeyUsageValue.CERTIFICATE_SIGN.name(),
                            Certificate.KeyUsageValue.CRL_SIGN.name()), Collections.emptyList());
            create(MIDDLE_ALIAS, HTTPS_ALIAS,
                    "CN=localhost, O=Odyssey, OU=Odyssey PKI, L=Novi Sad, C=Serbia",
                    new Date(), new Date(System.currentTimeMillis() + ROOT_EXPIRATION_MILLIS),
                    false, true, List.of(
                            Certificate.KeyUsageValue.DIGITAL_SIGNATURE.name(),
                            Certificate.KeyUsageValue.KEY_ENCIPHERMENT.name(),
                            Certificate.KeyUsageValue.KEY_AGREEMENT.name()), List.of("localhost", "*localhost"));
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    public void createRoot() throws IOException, GeneralSecurityException, OperatorCreationException {
        var keyPair = generateKeyPair();

        // SELF SIGNED SO THERE IS NO PARENT PRIVATE KEY
        var dn = X500NameFormatter.format("CN=Odyssey PKI Root, O=Odyssey, OU=Odyssey PKI, L=Novi Sad, C=Serbia");
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), dn)
                .withIssuer(keyPair.getPrivate(), keyPair.getPublic(), dn)
                .withExpiration(ROOT_EXPIRATION_MILLIS)
                .withAlias(ROOT_ALIAS)
                .setRootCertificate(true)
                .withKeyUsages(List.of(
                        Certificate.KeyUsageValue.DIGITAL_SIGNATURE.name(),
                        Certificate.KeyUsageValue.NON_REPUDIATION.name(),
                        Certificate.KeyUsageValue.CERTIFICATE_SIGN.name(),
                        Certificate.KeyUsageValue.CRL_SIGN.name()))
                .build();

        aclRepository.save(ROOT_ALIAS, encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        certificateRepository.saveRoot(certificate);
    }

    public List<X509Certificate> delete(String alias) throws IOException, GeneralSecurityException {
        if (ROOT_ALIAS.equals(alias))
            throw new IllegalArgumentException("Root certificate cannot be deleted.");

        return certificateRepository.delete(alias);
    }

    public X509Certificate find(String alias) throws IOException, GeneralSecurityException {
        return certificateRepository.find(alias);
    }

    public Map<String, X509Certificate> findAll() throws IOException, GeneralSecurityException {
        return certificateRepository.findAll();
    }

    public X509Certificate findByUid(Long uid) throws GeneralSecurityException, IOException {
        for (var certificate : findAll().values())
            if (certificate.getSubjectX500Principal().getName().contains("UID=" + uid))
                return certificate;
        return null;
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
}
