package com.example.odysseypki.dto;

import com.example.odysseypki.entity.Certificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
import java.util.List;
import java.util.Map;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CertificateCreationDTO {
    private String parentAlias;
    private String commonName;
    private String email;
    private String uid;
    private Long startDate;
    private Long endDate;
    private Boolean isHttpsCertificate;
    private Map<Certificate.Extension, List<String>> extensions;
}
