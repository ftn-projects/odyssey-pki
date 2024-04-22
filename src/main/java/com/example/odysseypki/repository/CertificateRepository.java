package com.example.odysseypki.repository;

import com.example.odysseypki.certificate.CertificateTree;
import com.example.odysseypki.entity.Certificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class CertificateRepository {
    private static final String ALIAS_TREE_PATH = "src/main/resources/static/alias-tree.dat";

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    public Certificate save(String parentAlias, Certificate certificate, PrivateKey key) throws IOException, GeneralSecurityException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        keyStoreRepository.save(certificate, key);
        tree.addAlias(parentAlias, certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);

        return certificate;
    }

    public void saveRoot(Certificate certificate, PrivateKey key) throws IOException, GeneralSecurityException {
        keyStoreRepository.createKeyStore();
        keyStoreRepository.save(certificate, key);

        var tree = CertificateTree.createTree(certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);
    }

    public X509Certificate find(String alias) throws IOException, GeneralSecurityException {
        return keyStoreRepository.load(alias);
    }

    public List<X509Certificate> findAll() throws IOException, GeneralSecurityException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        return keyStoreRepository.loadAll(tree.getAllAliases());
    }

    public String findParentAlias(String alias) throws IOException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        return tree.findParentAlias(alias);
    }

    public List<X509Certificate> delete(String alias) throws IOException, GeneralSecurityException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        var aliasesForDeletion = tree.removeAlias(alias);
        var deleted = new ArrayList<X509Certificate>();

        for (var a : aliasesForDeletion)
            deleted.add(keyStoreRepository.delete(a));

        tree.serialize(ALIAS_TREE_PATH);
        return deleted;
    }
}
