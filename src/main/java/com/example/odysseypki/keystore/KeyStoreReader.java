package com.example.odysseypki.keystore;

import com.example.odysseypki.entity.Issuer;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.stereotype.Component;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static java.util.Collections.emptyEnumeration;

@Component
public class KeyStoreReader {
    private KeyStore keyStore;

    public KeyStoreReader() {
        try {
            keyStore = KeyStore.getInstance("JKS", "SUN");
        } catch (KeyStoreException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public Certificate readCertificate(String keyStoreFile, String keyStorePass, String alias) {
        try {
            var ks = KeyStore.getInstance("JKS", "SUN");
            var in = new BufferedInputStream(new FileInputStream(keyStoreFile));
            ks.load(in, keyStorePass.toCharArray());

            if(ks.isKeyEntry(alias))
                return ks.getCertificate(alias);
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Enumeration<String> getAllAliases(String keyStoreFile, String keyStorePass) {
        try {
            var ks = KeyStore.getInstance("JKS", "SUN");
            var in = new BufferedInputStream(new FileInputStream(keyStoreFile));
            ks.load(in, keyStorePass.toCharArray());
            return keyStore.aliases();
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
        return Collections.emptyEnumeration();
    }
}
