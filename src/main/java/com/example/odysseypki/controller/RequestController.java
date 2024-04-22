package com.example.odysseypki.controller;


import com.example.odysseypki.dto.RequestDTO;
import com.example.odysseypki.entity.Request;
import com.example.odysseypki.mapper.RequestDTOMapper;
import com.example.odysseypki.service.RequestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin("http://localhost:4200")
@RestController
@RequestMapping(value = "/api/v1/requests")
public class RequestController {
    @Autowired
    private RequestService service;

    @GetMapping
    public ResponseEntity<?> getAll() {
        return new ResponseEntity<>(mapToDTO(service.getAll()), HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getRequestById(@PathVariable Long id) {
        Request request = service.findById(id);
        if (request == null) return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);

        return new ResponseEntity<>(RequestDTOMapper.fromRequestToDTO(request), HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> createRequest(@RequestBody RequestDTO dto) {
        Request request = RequestDTOMapper.fromDTOtoRequest(dto);
        service.create(request.getCommonName(),request.getEmail(),request.getUid(),request.getDate());

        return new ResponseEntity<>(RequestDTOMapper.fromRequestToDTO(request), HttpStatus.CREATED);
    }

    @PutMapping("/accept/{id}")
    public ResponseEntity<?> acceptRequest(@PathVariable Long id) {
        Request request = service.accept(id);

        return new ResponseEntity<>(RequestDTOMapper.fromRequestToDTO(request), HttpStatus.OK);
    }
    @PutMapping("/decline/{id}")
    public ResponseEntity<?> declineRequest(@PathVariable Long id) {
        Request request = service.decline(id);

        return new ResponseEntity<>(RequestDTOMapper.fromRequestToDTO(request), HttpStatus.OK);
    }
    private static List<RequestDTO> mapToDTO(List<Request> users) {
        return users.stream().map(RequestDTOMapper::fromRequestToDTO).toList();
    }
}
