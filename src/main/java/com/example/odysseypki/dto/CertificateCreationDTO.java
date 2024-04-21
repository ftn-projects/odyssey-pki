package com.example.odysseypki.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CertificateCreationDTO {
    private String parentAlias;
    private String commonName;
    private String email;
    private String uid;
    private Date startDate;
    private Date endDate;
}
