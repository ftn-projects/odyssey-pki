package com.example.odysseypki.dto;


import com.example.odysseypki.entity.Request;
import lombok.*;

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

    public RequestDTO(Request request){
        id = request.getId();
        commonName = request.getCommonName();
        email = request.getEmail();
        uid = request.getUid();
        date = request.getDate();
        status = request.getStatus();
    }
}
