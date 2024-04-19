package com.example.odysseypki.CertificateTree;

import com.example.odysseypki.entity.Certificate;

import java.util.ArrayList;
import java.util.List;

public class CertificateTree {
    private CertificateNode root;

    private void addChildCertificates(Certificate parentCertificate, CertificateNode parentNode, Certificate target) {

        if(parentCertificate.equals(parentNode.getCertificate())) {
            CertificateNode childNode = new CertificateNode(target);
            parentNode.addChild(childNode);
        } else {
            for(CertificateNode childNode : parentNode.getChildren()) {
                addChildCertificates(parentCertificate, childNode, target);
            }
        }
    }

    public List<Certificate> removeCertificate(Certificate toBeRemoved, CertificateNode parentNode){
        List<Certificate> deletedCertificates = new ArrayList<>();
        if (parentNode == null) {
            return deletedCertificates;
        }
        else{
            for(CertificateNode childNode : parentNode.getChildren()){
                if(childNode.getCertificate().equals(toBeRemoved)){
                    parentNode.removeChild(childNode);
                    deleteSubtree(childNode);
                    return deletedCertificates;
                }
            }
        }
        return deletedCertificates;
    }

    private List<Certificate> deleteSubtree(CertificateNode node){
        List<Certificate> deletedCertificates = new ArrayList<>();
        for(CertificateNode childNode : node.getChildren()){
            deletedCertificates.add(childNode.getCertificate());
            deletedCertificates.addAll(deleteSubtree(childNode));
        }
        return deletedCertificates;
    }
}
