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

@Component
public class CertificateRepository {
    private static final String KEYSTORE_PATH = "src/main/resources/static/keystore/certificate.jks";
    private static final String ALIAS_TREE_PATH = "src/main/resources/static/alias-tree.dat";

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    public void save(String parentAlias, Certificate certificate) throws IOException, ClassNotFoundException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        keyStoreRepository.save(certificate, KEYSTORE_PATH);
        tree.addCertificate(parentAlias, certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);
    }

    public void saveRoot(Certificate certificate) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        keyStoreRepository.createKeyStore(KEYSTORE_PATH);
        keyStoreRepository.save(certificate, KEYSTORE_PATH);

        var tree = CertificateTree.createTree(certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);
    }

    public X509Certificate load(String alias) {
        return keyStoreRepository.load(alias, KEYSTORE_PATH);
    }

    public void delete(String alias) throws IOException, ClassNotFoundException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        var aliasesForDeletion = tree.removeCertificate(alias);
        aliasesForDeletion.forEach(a -> keyStoreRepository.delete(a, KEYSTORE_PATH));
        tree.serialize(ALIAS_TREE_PATH);
    }
}
