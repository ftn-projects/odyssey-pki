package com.example.odysseypki.repository;

import com.example.odysseypki.entity.Request;
import org.bouncycastle.cert.ocsp.Req;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RequestRepository extends JpaRepository<Request, Long> {
    Request findByCommonName(String commonName);
}
