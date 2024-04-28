package com.example.odysseypki.controller;

import com.example.odysseypki.dto.CertificateCreationDTO;
import com.example.odysseypki.dto.CertificateDTO;
import com.example.odysseypki.entity.Certificate;
import com.example.odysseypki.service.CertificateService;
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


            //            // dodavanje signature ovde
//            sign = sifra(hash(bajtova));
//
//            // provera na frontu pre nego sto skine podatke
//            desifrovano = desifruj(sign, javniKljucHttps);
//            hash(primljenih bajtova) == desifrovano;


            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/x-x509-ca-cert"));
            headers.setContentDispositionFormData("attachment", "certificate.cer");

            return new ResponseEntity<>(certBytes, headers, HttpStatus.OK);
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
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

        // TODO please fix this hack (additional table in database)
        if (dto.getParentSerialNumber() == null && dto.getSubject().get("CN").equals("localhost")) {
            dto.setSerialNumber(CertificateService.HTTPS_ALIAS);
            dto.setParentSerialNumber("middle");
        }
        if (dto.getParentSerialNumber() == null && dto.getSubject().get("CN").equals("Odyssey PKI Middle")) {
            dto.setSerialNumber("middle");
            dto.setParentSerialNumber(CertificateService.ROOT_ALIAS);
        }
        else if (dto.getParentSerialNumber() == null && dto.getSubject().get("CN").equals("Odyssey PKI Root"))
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
