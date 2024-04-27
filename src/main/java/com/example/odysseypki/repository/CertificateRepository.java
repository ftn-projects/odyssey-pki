package com.example.odysseypki.repository;

import com.example.odysseypki.certificate.CertificateTree;
import com.example.odysseypki.certificate.InconsistentTreeException;
import com.example.odysseypki.entity.Certificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Component
public class CertificateRepository {
    private static final String ALIAS_TREE_PATH = "src/main/resources/static/alias-tree.dat";

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    public Certificate save(String parentAlias, Certificate certificate) throws IOException, GeneralSecurityException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        keyStoreRepository.save(certificate);
        tree.addAlias(parentAlias, certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);

        return certificate;
    }

    public void saveRoot(Certificate root) throws IOException, GeneralSecurityException {
        keyStoreRepository.createKeyStore();
        keyStoreRepository.save(root);

        var tree = CertificateTree.createTree(root.getAlias());
        tree.serialize(ALIAS_TREE_PATH);
    }

    public X509Certificate findByAlias(String alias) throws IOException, GeneralSecurityException {
        return keyStoreRepository.load(alias).orElseThrow();
    }

    public List<X509Certificate> findAll() throws IOException, CertificateException, KeyStoreException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        var certificates = new ArrayList<X509Certificate>();

        for (var a : tree.getAllAliases())
            certificates.add(keyStoreRepository.load(a)
                    .orElseThrow(() -> new InconsistentTreeException(a)));
        return certificates;
    }

    public String findParentAlias(String alias) throws IOException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        return tree.findParentAlias(alias);
    }

    public List<X509Certificate> delete(String alias) throws IOException, GeneralSecurityException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        // Transactional behavior (delete all or none)
        var aliasesForDeletion = tree.removeAliasAndSubtree(alias);
        for (var a : aliasesForDeletion)
            if (!keyStoreRepository.contains(a)) throw new InconsistentTreeException(a);

        var deleted = new ArrayList<X509Certificate>();
        for (var a : aliasesForDeletion)
            deleted.add(keyStoreRepository.delete(a).orElseThrow());

        tree.serialize(ALIAS_TREE_PATH);
        return deleted;
    }
}
