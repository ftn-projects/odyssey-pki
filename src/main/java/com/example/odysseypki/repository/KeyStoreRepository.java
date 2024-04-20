package com.example.odysseypki.repository;

import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.keystore.KeyStoreReader;
import com.example.odysseypki.keystore.KeyStoreWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.example.odysseypki.OdysseyPkiProperties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;

@Component
public class KeyStoreRepository {
    @Autowired
    private KeyStoreWriter keyStoreWriter;
    @Autowired
    private KeyStoreReader keyStoreReader;
    @Autowired
    private AclRepository aclRepository;

    public void save(Certificate certificate, String filepath) {
        var secret = getSecret().toCharArray();

        keyStoreWriter.loadKeyStore(filepath, secret);
        keyStoreWriter.write(certificate.getAlias(), certificate.getIssuer().getPrivateKey(), secret, certificate.getX509Certificate());
        keyStoreWriter.saveKeyStore(filepath, secret);
    }

    public void delete(String alias, String filepath) {
        keyStoreWriter.loadKeyStore(filepath, getSecret().toCharArray());
        keyStoreWriter.delete(alias);
        keyStoreWriter.saveKeyStore(filepath, getSecret().toCharArray());
    }

    public X509Certificate load(String alias, String filepath) {
        return (X509Certificate) keyStoreReader.readCertificate(filepath, getSecret(), alias);
    }

    public void createKeyStore(String filepath) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        try (FileOutputStream fos = new FileOutputStream(filepath)) {
            var keystorePassword = "aaa"; // TODO
            aclRepository.save("ks1", keystorePassword, AclRepository.KEYSTORE);
            keyStore.store(fos, keystorePassword.toCharArray());
        } catch (IllegalBlockSizeException | NoSuchPaddingException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private String getSecret() {
        try {
            return aclRepository.load("ks1", AclRepository.KEYSTORE);
        } catch (IOException | IllegalBlockSizeException | NoSuchPaddingException | BadPaddingException |
                 NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String generateKeystorePassword() {
            return BigInteger.valueOf(System.currentTimeMillis()).toString();
    }
}
