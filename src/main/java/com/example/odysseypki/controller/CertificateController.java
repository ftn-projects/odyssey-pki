package com.example.odysseypki.controller;

import com.example.odysseypki.dto.CertificateDTO;
import com.example.odysseypki.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

@RestController
@RequestMapping(value = "/api/v1/certificates")
public class CertificateController {
    @Autowired
    private CertificateService certificateService;

    @GetMapping("/{alias}")
    public ResponseEntity<?> getCertificate(@PathVariable String alias) {
        X509Certificate certificate = certificateService.get(alias);
        if (certificate == null) return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        return new ResponseEntity<>(certificate, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> createCertificate(@RequestBody CertificateDTO dto) throws IllegalBlockSizeException, NoSuchPaddingException,
            IOException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, ClassNotFoundException {
        certificateService.add(dto.getParentAlias(), dto.getCommonName(), dto.getEmail(), dto.getUid(), dto.getStartDate(), dto.getEndDate());
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @DeleteMapping("/{alias}")
    public ResponseEntity<?> deleteCertificate (@PathVariable String alias) throws IOException, ClassNotFoundException {
        certificateService.delete(alias);
        return new ResponseEntity<>(HttpStatus.OK);
    }

}
