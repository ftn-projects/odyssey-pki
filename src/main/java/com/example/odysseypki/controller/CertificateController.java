package com.example.odysseypki.controller;

import com.example.odysseypki.dto.CertificateCreationDTO;
import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.GeneralSecurityException;

@RestController
@RequestMapping(value = "/api/v1/certificates")
public class CertificateController {
    @Autowired
    private CertificateService service;

    @GetMapping
    public ResponseEntity<?> findAll() throws GeneralSecurityException, IOException, ClassNotFoundException {
        return new ResponseEntity<>(service.findAll(), HttpStatus.OK);
    }

    @GetMapping("/{alias}")
    public ResponseEntity<?> findByAlias(@PathVariable String alias) throws GeneralSecurityException, IOException {
        var certificate = service.find(alias);
        if (certificate == null) return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        return new ResponseEntity<>(certificate, HttpStatus.OK);
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
                dto.getEndDate()
        );
        return new ResponseEntity<>(created, HttpStatus.CREATED);
    }

    @DeleteMapping("/{alias}")
    public ResponseEntity<?> deleteByAlias(@PathVariable String alias) throws IOException, ClassNotFoundException, GeneralSecurityException {
        var deleted = service.delete(alias);
        return new ResponseEntity<>(deleted, HttpStatus.OK);
    }

}
