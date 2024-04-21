package com.example.odysseypki.service;

import com.example.odysseypki.entity.Request;
import com.example.odysseypki.repository.RequestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class RequestService {
    @Autowired
    private RequestRepository requestRepository;

    public List<Request> getAll() { return requestRepository.findAll(); }

    public Request findById(Long id) {
        return requestRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("There is no request with such id."));
    }

    public Request create(String commonName, String email, String uid, LocalDateTime date) {
        Request request = new Request(null, commonName, email, uid, date, Request.Status.PENDING);
        return requestRepository.save(request);
    }

    public Request accept(Long id) {
        Request request = findById(id);
        if (request.getStatus().equals(Request.Status.PENDING)) {
            request.setStatus(Request.Status.ACCEPTED);
            requestRepository.save(request);
        }
        return request;
    }

    public Request decline(Long id) {
        Request request = findById(id);
        if (request.getStatus().equals(Request.Status.PENDING)) {
            request.setStatus(Request.Status.DECLINED);
            requestRepository.save(request);
        }
        return request;
    }
}
