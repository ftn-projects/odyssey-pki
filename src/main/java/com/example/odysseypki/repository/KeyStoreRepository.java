package com.example.odysseypki.repository;

import com.example.odysseypki.OdysseyPkiProperties;
import com.example.odysseypki.entity.Certificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class KeyStoreRepository {

    @Autowired
    private OdysseyPkiProperties properties;

    public void save(Certificate certificate) throws IOException, CertificateException, KeyStoreException {
        var ks = loadKeyStore();

        ks.setKeyEntry(
                certificate.getAlias(),
                certificate.getPrivateKey(), getPassword(),
                new java.security.cert.Certificate[] {certificate.getX509Certificate()}
        );

        saveKeyStore(ks);
    }

    public X509Certificate delete(String alias) throws IOException, CertificateException, KeyStoreException {
        var certificate = load(alias);

        var ks = loadKeyStore();
        ks.deleteEntry(alias);
        saveKeyStore(ks);

        return certificate;
    }

    public X509Certificate load(String alias) throws IOException, CertificateException, KeyStoreException {
        var ks = loadKeyStore();

        if (ks.isKeyEntry(alias))
            return (X509Certificate) ks.getCertificate(alias);

        return null;
    }

    public List<X509Certificate> loadAll(List<String> aliases) throws IOException, CertificateException, KeyStoreException {
        var certificates = new ArrayList<X509Certificate>();

        for (var a : aliases)
            certificates.add(load(a));

        return certificates;
    }

    private KeyStore loadKeyStore() throws IOException, CertificateException {
        try {
            var ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(new FileInputStream(getFilePath()), getPassword());
            return ks;
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void saveKeyStore(KeyStore ks) throws IOException, CertificateException {
        try {
            ks.store(new FileOutputStream(getFilePath()), getPassword());
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void createKeyStore() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        var ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);

        try (var out = new FileOutputStream(getFilePath())) {
            ks.store(out, getPassword());
        }
    }

    public char[] getPassword() {
        return properties.getKeyStorePass().toCharArray();
    }

    public String getFilePath() {
        return properties.getKeyStorePath();
    }
}
