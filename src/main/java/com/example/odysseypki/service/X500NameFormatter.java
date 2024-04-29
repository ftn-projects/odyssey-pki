package com.example.odysseypki.service;

import org.bouncycastle.asn1.x500.X500Name;

import javax.security.auth.x500.X500Principal;
import java.util.*;
import java.util.stream.Collectors;

public class X500NameFormatter {

    private static final List<String> OrderedNames = List.of("CN", "UID", "OU", "O", "L", "ST", "C");

    public static X500Name format(X500Principal principal) {
        return format(principal.getName());
    }

    public static X500Name format(String name) {
        return format(Arrays.stream(name.split(","))
                .map(String::trim)
                .collect(Collectors.toMap(e -> e.split("=")[0], e -> e.split("=")[1])));
    }

    public static X500Name format(Map<String, String> name) {
        return new X500Name(name.entrySet().stream()
                .filter(e -> {
                    if (!OrderedNames.contains(e.getKey()))
                        System.out.println("Ignored DN attribute name: " + e.getKey());
                    return OrderedNames.contains(e.getKey());
                })
                .sorted(Map.Entry.comparingByKey(Comparator.comparingInt(OrderedNames::indexOf)))
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining(", ")));
    }

    public static Map<String, String> principalToMap(X500Principal principal) {
        return Arrays.stream(principal.getName().split(","))
                .map(String::trim)
                .filter(e -> OrderedNames.contains(e.split("=")[0]))
                .collect(Collectors.toMap(e -> e.split("=")[0], e -> e.split("=")[1]));
    }
}
