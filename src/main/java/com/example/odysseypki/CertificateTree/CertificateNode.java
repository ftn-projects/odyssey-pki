package com.example.odysseypki.CertificateTree;

import com.example.odysseypki.entity.Certificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class CertificateNode implements Serializable {
        private String alias;
        private List<CertificateNode> children;
        private CertificateNode parent;

        public CertificateNode(String alias, CertificateNode parent) {
            this.alias = alias;
            this.parent = parent;
            this.children = new ArrayList<>();
        }
        public void addChild(CertificateNode alias) {
            children.add(alias);
        }
        public void removeChild(CertificateNode alias) {
            children.remove(alias);
        }
}
