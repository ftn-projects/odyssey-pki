package com.example.odysseypki.service;

import com.example.odysseypki.acl.AclRepository;
import com.example.odysseypki.certificate.CertificateBuilder;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
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
    public static final String HTTPS_ALIAS = "https-certificate";

    @Autowired
    private AclRepository aclRepository;
    @Autowired
    private CertificateRepository certificateRepository;

    public Certificate create(String parentAlias, String commonName, Date startDate, Date endDate,
                              Map<Certificate.Extension, List<String>> extensions, boolean isHttpsCertificate)
            throws IOException, GeneralSecurityException, OperatorCreationException {
        return create(parentAlias, null,
                new X500Name("CN=" + commonName),
                startDate, endDate, extensions,
                isHttpsCertificate
        );
    }

    public Certificate create(String parentAlias, String alias, X500Name subjectName,
            Date startDate, Date endDate, Map<Certificate.Extension, List<String>> extensions, boolean isHttpsCertificate)
            throws IOException, GeneralSecurityException, OperatorCreationException {
        var parent = certificateRepository.find(parentAlias);
        if (parent == null)
            throw new IllegalArgumentException("Parent certificate with provided alias does not exist.");

        if (parent.getBasicConstraints() < 0)
            throw new IllegalArgumentException("Parent certificate is not a CA.");
        if (!keyUsageIsSubset(parent.getKeyUsage(), extensions))
            throw new IllegalArgumentException("Key usage of the new certificate must be a subset of the parent certificate key usage.");

        var parentPrivateKey = aclRepository.load(parentAlias, AclRepository.PRIVATE_KEYS_ACL);
        if (parentPrivateKey == null) return null;

        var keyPair = generateKeyPair();
        if (keyPair == null) return null;

        var issuerName = new X500Name(parent.getSubjectX500Principal().getName());
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), subjectName)
                .withIssuer(decodePrivateKey(parentPrivateKey), parent.getPublicKey(), issuerName)
                .withStartDate(startDate)
                .withEndDate(endDate)
                .withAlias(alias)
                .withPrivateKey(isHttpsCertificate ? keyPair.getPrivate() : null)
                .withExtensions(extensions)
                .build();

        aclRepository.save(certificate.getAlias(), encodePrivateKey(keyPair.getPrivate()), AclRepository.PRIVATE_KEYS_ACL);
        return certificateRepository.save(parentAlias, certificate);
    }

    public Certificate createHttpsCertificate(String parentAlias, String commonName, Date startDate, Date endDate) throws GeneralSecurityException, IOException, OperatorCreationException {
        return create(parentAlias, commonName, startDate, endDate,
                Map.of(
                        Certificate.Extension.BASIC_CONSTRAINTS, List.of(String.valueOf(false)),
                        Certificate.Extension.KEY_USAGE, List.of(
                                Certificate.KeyUsageValue.DIGITAL_SIGNATURE.name(),
                                Certificate.KeyUsageValue.KEY_ENCIPHERMENT.name(),
                                Certificate.KeyUsageValue.KEY_AGREEMENT.name()),
                        Certificate.Extension.SUBJECT_KEY_IDENTIFIER, List.of(),
                        Certificate.Extension.AUTHORITY_KEY_IDENTIFIER, List.of()),
                true);
    }

    private boolean keyUsageIsSubset(boolean[] keyUsage, Map<Certificate.Extension, List<String>> extensions) {
        List<String> keyUsageValues = extensions.get(Certificate.Extension.KEY_USAGE);
        if (keyUsageValues == null) return true;

        return keyUsageValues.stream().allMatch(usage -> {
            try {
                var keyUsageEnum = Certificate.KeyUsageValue.valueOf(usage);
                return keyUsage[keyUsageEnum.ordinal()];
            } catch (IllegalArgumentException e) {
                return false;
            }
        });
    }

    public void initializeKeyStore() {
        try {
            createRoot();
            create(ROOT_ALIAS, HTTPS_ALIAS,
                    new X500Name("CN=localhost"),
                    new Date(), new Date(System.currentTimeMillis() + ROOT_EXPIRATION_MILLIS),
                    Map.of(
                            Certificate.Extension.BASIC_CONSTRAINTS, List.of(String.valueOf(false)),
                            Certificate.Extension.KEY_USAGE, List.of(
                                    Certificate.KeyUsageValue.DIGITAL_SIGNATURE.name(),
                                    Certificate.KeyUsageValue.KEY_ENCIPHERMENT.name(),
                                    Certificate.KeyUsageValue.KEY_AGREEMENT.name()),
                            Certificate.Extension.SUBJECT_KEY_IDENTIFIER, List.of(),
                            Certificate.Extension.AUTHORITY_KEY_IDENTIFIER, List.of(),
                            Certificate.Extension.SUBJECT_ALTERNATIVE_NAME, List.of("localhost", "*localhost")),
                    true
            );
        } catch (IOException | GeneralSecurityException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    public void createRoot() throws IOException, GeneralSecurityException, OperatorCreationException {
        var keyPair = generateKeyPair();

        // SELF SIGNED SO THERE IS NO PARENT PRIVATE KEY
        var x500Name = new X500Name("CN=Odyssey PKI Root");
        var allKeyUsages = Arrays.stream(Certificate.KeyUsageValue.values()).map(Certificate.KeyUsageValue::name).toList();
        var certificate = new CertificateBuilder()
                .withSubject(keyPair.getPublic(), x500Name)
                .withIssuer(keyPair.getPrivate(), keyPair.getPublic(), x500Name)
                .withExpiration(ROOT_EXPIRATION_MILLIS)
                .withAlias(ROOT_ALIAS)
                .withExtensions(Map.of(
                        Certificate.Extension.BASIC_CONSTRAINTS, List.of(String.valueOf(true)),
                        Certificate.Extension.KEY_USAGE, allKeyUsages,  // ROOT CERTIFICATE CAN PERFORM ALL ACTIONS
                        Certificate.Extension.SUBJECT_KEY_IDENTIFIER, List.of()
                ))
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

    public X509Certificate findByCommonName(String commonName) throws GeneralSecurityException, IOException {
        for (var c : findAll())
            if (c.getSubjectX500Principal().getName().toLowerCase().contains(commonName))
                return c;
        return null;
    }
}
