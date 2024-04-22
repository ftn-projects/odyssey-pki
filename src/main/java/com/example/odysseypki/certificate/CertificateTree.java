package com.example.odysseypki.certificate;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

@Getter
@Setter
@AllArgsConstructor
public class CertificateTree implements Serializable {
    @Serial
    private static final long serialVersionUID = 81723617236L;

    private CertificateNode root;

    public List<String> getAllAliases() {
        var aliases = new ArrayList<String>();
        dipTraverse(root, node -> aliases.add(node.getAlias()));
        return aliases;
    }

    public String findParentAlias(String alias) {
        var parent = new AtomicReference<String>();

        dipTraverse(root, node -> {
            if (node != null && node.getAlias().equals(alias) && node.getParent() != null)
                parent.set(node.getParent().getAlias());
        });

        return parent.get();
    }

    private void addAlias(String parentAlias, String newAlias, CertificateNode currentNode) {
        if(parentAlias.equals(currentNode.getAlias())) {
            CertificateNode childNode = new CertificateNode(newAlias, currentNode);
            currentNode.addChild(childNode);

        } else {
            for(CertificateNode childNode : currentNode.getChildren()) {
                addAlias(parentAlias, newAlias, childNode);
            }
        }
    }

    public void addAlias(String parentAlias, String newAlias) {
        addAlias(parentAlias, newAlias, root);
    }

    public static CertificateTree createTree(String rootAlias) {
        return new CertificateTree(new CertificateNode(rootAlias));
    }

    public List<String> removeAlias(String toBeRemoved){
        if (root == null) {
            return null;
        }
        else if (root.getAlias().equals(toBeRemoved)){
            List<String> deletedCertificates = new ArrayList<>();
            if (root.getChildren() != null) {
                for (CertificateNode childNode : root.getChildren()) {
                    deletedCertificates.addAll(scanSubtree(childNode));
                }
            }
            this.root = null;
            return deletedCertificates;
        }
        else {
            return removeAlias(toBeRemoved, this.root);
        }
    }
    private List<String> removeAlias(String toBeRemoved, CertificateNode currentNode){

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
            var returns = removeAlias(toBeRemoved, childNode);
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

    // Generic tree traversal with function to be performed on each node
    // Can be used for deletion and printing (if depth is added to the CertificateNode)
    private void dipTraverse(CertificateNode node, Consumer<CertificateNode> consumer) {
        consumer.accept(node);

        if (node == null || node.getChildren() == null)
            return;

        for (CertificateNode child : node.getChildren())
            dipTraverse(child, consumer);
    }

    private void printNode(CertificateNode node, int depth) {
        String sb = "\t".repeat(Math.max(0, depth)) + "|-- " + node.getAlias();
        System.out.println(sb);

        for (CertificateNode child : node.getChildren())
            printNode(child, depth + 1);
    }

    public void serialize(String fileName) throws IOException {
        File file = new File(fileName);
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
            oos.writeObject(this);
        }
    }

    public static CertificateTree deserialize(String fileName) throws IOException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName))) {
            return (CertificateTree) ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
