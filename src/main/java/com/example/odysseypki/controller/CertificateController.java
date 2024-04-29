package com.example.odysseypki.controller;

import com.example.odysseypki.dto.CertificateCreationDTO;
import com.example.odysseypki.dto.CertificateDTO;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.service.CertificateService;
import com.example.odysseypki.service.X500NameFormatter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

@CrossOrigin("https://localhost:4200")
@RestController
@RequestMapping(value = "/api/v1/certificates")
public class CertificateController {
    @Autowired
    private CertificateService service;

    @GetMapping
    public ResponseEntity<?> findAll() throws GeneralSecurityException, IOException {
        var certificates = new ArrayList<CertificateDTO>();

        for (var entry : service.findAll().entrySet())
            certificates.add(mapCertificateToDTO(entry.getKey(), entry.getValue()));

        return new ResponseEntity<>(certificates, HttpStatus.OK);
    }

    @GetMapping("/{alias}")
    public ResponseEntity<?> findByAlias(@PathVariable String alias) throws GeneralSecurityException, IOException {
        var certificate = service.find(alias);

        if (certificate == null)
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);

        return new ResponseEntity<>(mapCertificateToDTO(alias, certificate), HttpStatus.OK);
    }

    @GetMapping(value = "/download/{name}/{surname}", produces = "application/x-x509-ca-cert")
    public ResponseEntity<byte[]> findByCommonName(@PathVariable String name, @PathVariable String surname) {
        try {
            var certificate = service.findByCommonName(
                    name.trim().toLowerCase() + " " + surname.trim().toLowerCase()
            );

            if (certificate == null)
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);

            // Get bytes from certificate
            byte[] certBytes = certificate.getEncoded();

            return new ResponseEntity<>(certBytes, HttpStatus.OK);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/has/{name}/{surname}")
    public ResponseEntity<?> hasCertificate(@PathVariable String name, @PathVariable String surname) throws GeneralSecurityException, IOException {
        // TODO check by using database
        var certificate = service.findByCommonName(
                name.trim().toLowerCase() + " " + surname.trim().toLowerCase()
        );
        return new ResponseEntity<>(certificate != null, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody CertificateCreationDTO dto) throws GeneralSecurityException,
            IOException, OperatorCreationException {
        Certificate created;
        // TODO make it work
        if (dto.getIsHttps() != null && dto.getIsHttps()) {
            created = service.createHttpsCertificate(
                    dto.getParentAlias(), dto.getCommonName(),
                    new Date(dto.getStartDate()), new Date(dto.getEndDate())
            );
        } else {
            created = service.create(
                    dto.getParentAlias(), dto.getCommonName(),
                    new Date(dto.getStartDate()), new Date(dto.getEndDate()),
                    new HashMap<>(), false
            );
        }
        return new ResponseEntity<>(mapCertificateToDTO(created.getAlias(), created.getX509Certificate()), HttpStatus.CREATED);
    }

    @DeleteMapping("/{alias}")
    public ResponseEntity<?> deleteByAlias(@PathVariable String alias) throws IOException, GeneralSecurityException {
        var certificates = new ArrayList<CertificateDTO>();

        for (var certificate : service.delete(alias))
            certificates.add(mapCertificateToDTO(alias, certificate));

        return new ResponseEntity<>(certificates, HttpStatus.OK);
    }

    private CertificateDTO mapCertificateToDTO(String alias, X509Certificate certificate) throws IOException, CertificateEncodingException {
        return new CertificateDTO(
                alias,
                service.findParentAlias(alias),
                X500NameFormatter.principalToMap(certificate.getIssuerX500Principal()),
                X500NameFormatter.principalToMap(certificate.getSubjectX500Principal()),
                new CertificateDTO.Validity(certificate),
                new CertificateDTO.PublicKey(certificate),
                ExtensionMapper.readExtensions(certificate),
                new CertificateDTO.Signature(certificate)
        );
    }
}
