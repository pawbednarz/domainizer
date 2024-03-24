package com.domainizer.domainscanner.controller;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.repository.DomainRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class DomainController {

    private final DomainRepository DomainRepository;

    @Autowired
    public DomainController(DomainRepository DomainRepository) {
        this.DomainRepository = DomainRepository;
    }

    @GetMapping("/domain")
    public ResponseEntity<List<Domain>> getDomains() {
        List<Domain> domains = DomainRepository.findAll();
        return ResponseEntity.ok(domains);
    }
}