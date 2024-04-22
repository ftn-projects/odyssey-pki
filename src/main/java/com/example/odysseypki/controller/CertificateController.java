package com.example.odysseypki.controller;

import com.example.odysseypki.dto.CertificateCreationDTO;
import com.example.odysseypki.dto.CertificateDTO;
import com.example.odysseypki.entity.Certificate;
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
import java.util.*;

@CrossOrigin("http://localhost:4200")
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
    public ResponseEntity<?> findByAlias(@PathVariable String alias) throws GeneralSecurityException, IOException {
        var certificate = service.find(alias);

        if (certificate == null)
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        return new ResponseEntity<>(mapCertificateToDTO(certificate), HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody CertificateCreationDTO dto) throws GeneralSecurityException,
            IOException, OperatorCreationException {
        Certificate created;

        if (dto.getIsHttpsCertificate() != null && dto.getIsHttpsCertificate()) {
            created = service.createHttpsCertificate(
                    dto.getParentAlias(), dto.getCommonName(),
                    new Date(dto.getStartDate()), new Date(dto.getEndDate())
            );
        } else {
            created = service.create(
                    dto.getParentAlias(), dto.getCommonName(),
                    new Date(dto.getStartDate()), new Date(dto.getEndDate()),
                    dto.getExtensions(), false
            );
        }
        return new ResponseEntity<>(mapCertificateToDTO(created.getX509Certificate()), HttpStatus.CREATED);
    }

    @DeleteMapping("/{alias}")
    public ResponseEntity<?> deleteByAlias(@PathVariable String alias) throws IOException, GeneralSecurityException {
        var certificates = new ArrayList<CertificateDTO>();

        for (var certificate : service.delete(alias))
            certificates.add(mapCertificateToDTO(certificate));

        return new ResponseEntity<>(certificates, HttpStatus.OK);
    }

    private CertificateDTO mapCertificateToDTO(X509Certificate certificate) throws IOException, CertificateEncodingException {
        var alias = certificate.getSerialNumber().toString();
        var dto = new CertificateDTO(
                alias,
                service.findParentAlias(alias),
                mapX500Principal(certificate.getIssuerX500Principal()),
                mapX500Principal(certificate.getSubjectX500Principal()),
                new CertificateDTO.PublicKey(certificate),
                new CertificateDTO.Validity(certificate),
                ExtensionMapper.readExtensions(certificate),
                new CertificateDTO.Signature(certificate)
        );
        if (dto.getParentSerialNumber() == null && dto.getSubject().get("CN").equals("Https Certificate")) {
            dto.setSerialNumber(CertificateService.HTTPS_ALIAS);
            dto.setParentSerialNumber(CertificateService.ROOT_ALIAS);
        }
        else if (dto.getParentSerialNumber() == null && dto.getSubject().get("CN").equals("Root Certificate"))
            dto.setSerialNumber(CertificateService.ROOT_ALIAS);
        return dto;
    }

    private static Map<String, String> mapX500Principal(X500Principal principal) {
        var map = new HashMap<String, String>();
        var parts = principal.getName().split(",");
        var dns = List.of("CN", "E", "UID");

        for (String part : parts) {
            var tokens = part.trim().split("=");
            if (dns.contains(tokens[0]))
                map.put(tokens[0], tokens[1]);
        }

        return map;
    }
}
