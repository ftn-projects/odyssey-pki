package com.example.odysseypki.CertificateTree;

import com.example.odysseypki.entity.Certificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class CertificateNode {
        private Certificate certificate;
        private List<CertificateNode> children;

        public CertificateNode(Certificate certificate) {
            this.certificate = certificate;
            this.children = new ArrayList<>();
        }
        public void addChild(CertificateNode child) {
            children.add(child);
        }
        public void removeChild(CertificateNode child) {
            children.remove(child);
        }
}
