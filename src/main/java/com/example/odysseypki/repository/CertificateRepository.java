package com.example.odysseypki.repository;

import com.example.odysseypki.certificate.CertificateTree;
import com.example.odysseypki.entity.Certificate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Component
public class CertificateRepository {
    public static final String KEYSTORE_PATH = "src/main/resources/static/keystore/certificate.jks";
    private static final String ALIAS_TREE_PATH = "src/main/resources/static/alias-tree.dat";

    @Autowired
    private KeyStoreRepository keyStoreRepository;

    public Certificate save(String parentAlias, Certificate certificate) throws GeneralSecurityException, IOException, ClassNotFoundException {
        keyStoreRepository.save(certificate, KEYSTORE_PATH);

        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        tree.addAlias(parentAlias, certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);

        return certificate;
    }

    public Certificate saveRoot(Certificate certificate) throws GeneralSecurityException, IOException {
        keyStoreRepository.createKeyStore(KEYSTORE_PATH);
        keyStoreRepository.save(certificate, KEYSTORE_PATH);

        var tree = CertificateTree.createTree(certificate.getAlias());
        tree.serialize(ALIAS_TREE_PATH);

        return certificate;
    }

    public X509Certificate find(String alias) throws GeneralSecurityException, IOException {
        return keyStoreRepository.load(alias, KEYSTORE_PATH);
    }

    public List<X509Certificate> findAll() throws GeneralSecurityException, IOException, ClassNotFoundException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        return keyStoreRepository.loadAll(tree.getAllAliases(), KEYSTORE_PATH);
    }

    public String getRootAlias() throws IOException, ClassNotFoundException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        return tree.getRootAlias();
    }

    public String findParentAlias(String alias) throws IOException, ClassNotFoundException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);
        return tree.findParentAlias(alias);
    }

    public List<X509Certificate> delete(String alias) throws IOException, ClassNotFoundException, GeneralSecurityException {
        var tree = CertificateTree.deserialize(ALIAS_TREE_PATH);

        if (tree.getRootAlias().equals(alias))
            throw new IllegalArgumentException("Root certificate cannot be deleted.");

        var aliasesForDeletion = tree.removeAlias(alias);
        var deleted = new ArrayList<X509Certificate>();

        for (var a : aliasesForDeletion)
            deleted.add(keyStoreRepository.delete(a, KEYSTORE_PATH));

        tree.serialize(ALIAS_TREE_PATH);
        return deleted;
    }
}
