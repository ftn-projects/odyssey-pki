package com.example.odysseypki.repository;

import com.example.odysseypki.certificatetree.CertificateTree;
import com.example.odysseypki.entity.Certificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.X509Certificate;

@Component
public class CertificateRepository {
    private static final String CERT_KS_PATH = "src/main/resources/static/cert.jks";
    private static final String ALIAS_TREE_PATH = "src/main/resources/static/alias.dat";

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    public void save(String parentAlias, Certificate certificate) throws IOException, ClassNotFoundException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        keyStoreRepository.save(certificate, CERT_KS_PATH);
        tree.addCertificate(parentAlias, certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);
    }

    public X509Certificate load(String alias) {
        return keyStoreRepository.load(alias, CERT_KS_PATH);
    }

    public void delete(String alias) throws IOException, ClassNotFoundException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        // TODO keyStoreRepository.delete(alias);
        tree.removeCertificate(alias);
        tree.serialize(ALIAS_TREE_PATH);
    }
}
