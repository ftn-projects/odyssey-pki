package com.example.odysseypki.controller;

import com.example.odysseypki.dto.CertificateCreationDTO;
import com.example.odysseypki.dto.CertificateDTO;
import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(value = "/api/v1/certificates")
public class CertificateController {
    @Autowired
    private CertificateService service;

    @GetMapping
    public ResponseEntity<?> findAll() throws GeneralSecurityException, IOException, ClassNotFoundException {
        var certificates = new ArrayList<CertificateDTO>();

        for (var certificate : service.findAll())
            certificates.add(mapCertificateToDTO(certificate));

        return new ResponseEntity<>(certificates, HttpStatus.OK);
    }

    @GetMapping("/{alias}")
    public ResponseEntity<?> findByAlias(@PathVariable String alias) throws GeneralSecurityException, IOException, ClassNotFoundException {
        var certificate = service.find(alias);

        if (certificate == null)
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        return new ResponseEntity<>(mapCertificateToDTO(certificate), HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody CertificateCreationDTO dto) throws GeneralSecurityException,
            IOException, ClassNotFoundException, OperatorCreationException {
        var created = service.create(
                dto.getParentAlias(),
                dto.getCommonName(),
                dto.getEmail(),
                dto.getUid(),
                dto.getStartDate(),
                dto.getEndDate(),
                dto.getExtensions()
        );
        return new ResponseEntity<>(created, HttpStatus.CREATED);
    }

    @DeleteMapping("/{alias}")
    public ResponseEntity<?> deleteByAlias(@PathVariable String alias) throws IOException, ClassNotFoundException, GeneralSecurityException {
        var deleted = service.delete(alias);
        return new ResponseEntity<>(deleted, HttpStatus.OK);
    }

    private CertificateDTO mapCertificateToDTO(X509Certificate certificate) throws IOException, ClassNotFoundException, CertificateEncodingException {
        var alias = certificate.getSerialNumber().toString();
        return new CertificateDTO(
                alias,
                service.findParentAlias(alias),
                mapX500Principal(certificate.getIssuerX500Principal()),
                mapX500Principal(certificate.getSubjectX500Principal()),
                new CertificateDTO.PublicKey(certificate),
                new CertificateDTO.Validity(certificate),
                ExtensionMapper.readExtensions(certificate),
                new CertificateDTO.Signature(certificate)
        );
    }

    private static Map<String, String> mapX500Principal(X500Principal principal) {
        var map = new HashMap<String, String>();
        var parts = principal.getName().split(",");

        for (String part : parts) {
            part = part.trim();
            if (part.startsWith("CN="))
                map.put("CN", part.substring(3));
            else if (part.startsWith("E="))
                map.put("E", part.substring(2));
            else if (part.startsWith("UID="))
                map.put("UID", part.substring(4));
        }
        return map;
    }
}
