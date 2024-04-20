package com.example.odysseypki.controller;

import com.example.odysseypki.dto.CertificateDTO;
import com.example.odysseypki.service.CertificateService;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

@RestController
@RequestMapping(value = "/api/v1/certificates")
public class CertificateController {
    @Autowired
    private CertificateService certificateService;

    @GetMapping
    public ResponseEntity<?> findAll() {
        return new ResponseEntity<>(certificateService.findAll(), HttpStatus.OK);
    }

    @GetMapping("/{alias}")
    public ResponseEntity<?> findByAlias(@PathVariable String alias) {
        X509Certificate certificate = certificateService.find(alias);
        if (certificate == null) return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        return new ResponseEntity<>(certificate, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> create(@RequestBody CertificateDTO dto) throws GeneralSecurityException,
            IOException, ClassNotFoundException, OperatorCreationException {
        certificateService.create(dto.getParentAlias(), dto.getCommonName(), dto.getEmail(), dto.getUid(), dto.getStartDate(), dto.getEndDate());
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @DeleteMapping("/{alias}")
    public ResponseEntity<?> deleteByAlias(@PathVariable String alias) throws IOException, ClassNotFoundException {
        certificateService.delete(alias);
        return new ResponseEntity<>(HttpStatus.OK);
    }

}
