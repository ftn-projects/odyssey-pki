package com.example.odysseypki.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.PublicKey;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Subject {
    private PublicKey publicKey;
    private X500Name x500Name;
}
