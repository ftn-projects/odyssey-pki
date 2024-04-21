package com.example.odysseypki.dto;


import com.example.odysseypki.entity.Request;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RequestDTO {
    private Long id;
    private String commonName;
    private String email;
    private String uid;
    private LocalDateTime date;
    private Request.Status status;
}
