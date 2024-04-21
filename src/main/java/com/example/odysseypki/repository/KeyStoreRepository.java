package com.example.odysseypki.repository;

import com.example.odysseypki.acl.AclRepository;
import com.example.odysseypki.entity.Certificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Component
public class KeyStoreRepository {
    private static final String KEYSTORE_PASSWORD_ID = "kspass";
    @Autowired
    private AclRepository aclRepository;

    public void save(Certificate certificate, String filepath) throws GeneralSecurityException, IOException {
        var ks = loadKeyStore(filepath, getSecret());

        ks.setKeyEntry(
                certificate.getAlias(),
                certificate.getIssuer().getPrivateKey(),
                getSecret().toCharArray(),
                new java.security.cert.Certificate[] {certificate.getX509Certificate()}
        );

        saveKeyStore(ks, filepath, getSecret());
    }

    public X509Certificate delete(String alias, String filepath) throws GeneralSecurityException, IOException {
        var certificate = load(alias, filepath);
        var ks = loadKeyStore(filepath, getSecret());

        ks.deleteEntry(alias);
        saveKeyStore(ks, filepath, getSecret());

        return certificate;
    }

    public X509Certificate load(String alias, String filepath) throws GeneralSecurityException, IOException {
        var ks = loadKeyStore(filepath, getSecret());

        if (ks.isKeyEntry(alias))
            return (X509Certificate) ks.getCertificate(alias);

        return null;
    }

    public List<X509Certificate> loadAll(List<String> aliases, String filepath) throws GeneralSecurityException, IOException {
        var certificates = new ArrayList<X509Certificate>();
        for (var a : aliases)
            certificates.add(load(a, filepath));
        return certificates;
    }

    private KeyStore loadKeyStore(String filepath, String password) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        var ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(filepath), password.toCharArray());
        return ks;
    }

    private void saveKeyStore(KeyStore ks, String filepath, String password) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        ks.store(new FileOutputStream(filepath), password.toCharArray());
    }

    public void createKeyStore(String filepath) throws GeneralSecurityException, IOException {
        var ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);

        try (var out = new FileOutputStream(filepath)) {
            var keyStorePass = "aaa"; // TODO
            aclRepository.save(KEYSTORE_PASSWORD_ID, keyStorePass, AclRepository.KEYSTORES_ACL_PATH);
            ks.store(out, keyStorePass.toCharArray());
        }
    }

    private String getSecret() {
        try {
            return aclRepository.load(KEYSTORE_PASSWORD_ID, AclRepository.KEYSTORES_ACL_PATH);
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String generateKeystorePassword() {
        return BigInteger.valueOf(System.currentTimeMillis()).toString();
    }
}
