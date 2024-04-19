package com.example.odysseypki.repository;

import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.keystore.KeyStoreReader;
import com.example.odysseypki.keystore.KeyStoreWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.example.odysseypki.OdysseyPkiProperties;

import java.security.cert.X509Certificate;

@Component
public class KeyStoreRepository {
    @Autowired
    private KeyStoreWriter keyStoreWriter;
    @Autowired
    private KeyStoreReader keyStoreReader;
    @Autowired
    private OdysseyPkiProperties properties;

    public void save(Certificate certificate, String  filepath){
        var secret = properties.getSecret().toCharArray();

        keyStoreWriter.loadKeyStore(filepath, secret);
        keyStoreWriter.write("root", certificate.getIssuer().getPrivateKey(), secret, certificate.getX509Certificate());
        keyStoreWriter.saveKeyStore(filepath, secret);
    }

    public X509Certificate load(String alias,String filepath){
        return (X509Certificate) keyStoreReader.readCertificate(filepath, properties.getSecret(), alias);
    }
}
