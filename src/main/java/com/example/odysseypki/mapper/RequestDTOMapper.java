package com.example.odysseypki.mapper;

import com.example.odysseypki.entity.Request;
import com.example.odysseypki.dto.RequestDTO;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class RequestDTOMapper {
    private static ModelMapper mapper;

    @Autowired
    public RequestDTOMapper(ModelMapper mapper) {
        RequestDTOMapper.mapper = mapper;
    }
    public static Request fromDTOtoRequest(RequestDTO dto) {
        return mapper.map(dto, Request.class);
    }
    public static RequestDTO fromRequestToDTO(Request request) {
        return new RequestDTO(request);
    }
}
