package com.example.odysseypki.certificatetree;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Getter
@Setter
@AllArgsConstructor
public class CertificateTree implements Serializable {
    private CertificateNode root;

    public CertificateNode findByAlias(String alias) {
        if (root == null || alias == null || alias.isEmpty()) {
            return null;
        }
        return findByAlias(root, alias);
    }

    private CertificateNode findByAlias(CertificateNode node, String alias) {
        if (node.getAlias().equals(alias)) {
            return node;
        }
        for (CertificateNode child : node.getChildren()) {
            CertificateNode result = findByAlias(child, alias);
            if (result != null) {
                return result;
            }
        }
        return null;
    }

    public String getRootAlias() {
        return root.getAlias();
    }

    private void addCertificates(String parentAlias, String newAlias, CertificateNode currentNode) {
        if(parentAlias.equals(currentNode.getAlias())) {
            //Ignore this, this is just for texting -Arezina
            //System.out.println("Inserting into Alias: " + currentNode.getAlias() + " New Alias: " + newAlias);
            CertificateNode childNode = new CertificateNode(newAlias, currentNode);
            currentNode.addChild(childNode);

        } else {
            for(CertificateNode childNode : currentNode.getChildren()) {
                addCertificates(parentAlias, newAlias, childNode);
            }
        }
    }

    public void addCertificate(String parentAlias, String newAlias) {
        addCertificates(parentAlias, newAlias, root);
    }

    public static CertificateTree createTree(String rootAlias) {
        return new CertificateTree(new CertificateNode(rootAlias));
    }

    public List<String> removeCertificate(String toBeRemoved){
        if (root == null) {
            return null;
        }
        else if(root.getAlias().equals(toBeRemoved)){
            List<String> deletedCertificates = new ArrayList<>();
            if (root.getChildren() != null) {
                for (CertificateNode childNode : root.getChildren()) {
                    deletedCertificates.addAll(scanSubtree(childNode));
                }
            }
            this.root = null;
            return deletedCertificates;
        }
        else{
            return removeCertificate(toBeRemoved, this.root);
        }
    }
    private List<String> removeCertificate(String toBeRemoved, CertificateNode currentNode){

        if(currentNode.getAlias().equals(toBeRemoved)){
            CertificateNode parent = currentNode.getParent();
            if(parent==null) {
                this.root = null;
                return scanSubtree(currentNode);
            }
            parent.removeChild(currentNode);
            return scanSubtree(currentNode);
        }

        for(CertificateNode childNode : currentNode.getChildren()){
            var returns = removeCertificate(toBeRemoved, childNode);
            if(returns!=null)
                return returns;
        }
        return null;
    }

    private List<String> scanSubtree(CertificateNode node){
        List<String> deletedCertificates = new ArrayList<>();
        deletedCertificates.add(node.getAlias());
        for(CertificateNode childNode : node.getChildren()){
            deletedCertificates.addAll(scanSubtree(childNode));
        }
        return deletedCertificates;
    }

    public void printTree() {
        if (root == null) {
            System.out.println("Certificate tree is empty.");
        } else {
            System.out.println("Certificate tree:");
            printNode(root, 0);
        }
    }

    private void printNode(CertificateNode node, int depth) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            sb.append("\t");
        }
        sb.append("|-- ");
        sb.append(node.getAlias());
        System.out.println(sb.toString());

        for (CertificateNode child : node.getChildren()) {

            printNode(child, depth + 1);
        }
    }

    public void serialize(String fileName) throws IOException {
        File file = new File(fileName);
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
            oos.writeObject(this);
        }
    }

    public static CertificateTree deserialize(String fileName) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName))) {
            CertificateTree tree = (CertificateTree) ois.readObject();
            System.out.println("Certificate tree deserialized successfully.");
            return tree;
        }
    }
}