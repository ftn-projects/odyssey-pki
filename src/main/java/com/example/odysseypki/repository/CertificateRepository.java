package com.example.odysseypki.repository;

import com.example.odysseypki.certificatetree.CertificateTree;
import com.example.odysseypki.entity.Certificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

@Component
public class CertificateRepository {
    private static final String KEYSTORE_PATH = "src/main/resources/static/keystore/certificate.jks";
    private static final String ALIAS_TREE_PATH = "src/main/resources/static/alias-tree.dat";

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    public Certificate save(String parentAlias, Certificate certificate) throws IOException, ClassNotFoundException {
        keyStoreRepository.save(certificate, KEYSTORE_PATH);

        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        tree.addCertificate(parentAlias, certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);
        return certificate;
    }

    public Certificate saveRoot(Certificate certificate) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        keyStoreRepository.createKeyStore(KEYSTORE_PATH);
        keyStoreRepository.save(certificate, KEYSTORE_PATH);

        var tree = CertificateTree.createTree(certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);
        return certificate;
    }

    public X509Certificate find(String alias) {
        return keyStoreRepository.load(alias, KEYSTORE_PATH);
    }

    public List<X509Certificate> findAll() {
        return keyStoreRepository.loadAll(KEYSTORE_PATH);
    }

    public String getRootAlias() {
        try {
            var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
            return tree.getRootAlias();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void delete(String alias) throws IOException, ClassNotFoundException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        var aliasesForDeletion = tree.removeCertificate(alias);
        aliasesForDeletion.forEach(a -> keyStoreRepository.delete(a, KEYSTORE_PATH));
        tree.serialize(ALIAS_TREE_PATH);
    }
}
