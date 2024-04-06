package com.domainizer.export.controller;

import com.domainizer.domainscanner.repository.ScanRepository;
import com.domainizer.export.service.StatisticsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/statistics")
public class StatisticsController {

    StatisticsService statisticsService;
    ScanRepository scanRepository;

    @Autowired
    public StatisticsController(StatisticsService statisticsService, ScanRepository scanRepository) {
        this.statisticsService = statisticsService;
        this.scanRepository = scanRepository;
    }

    @GetMapping("/vulnerabilities")
    public ResponseEntity<Map<String, Integer>> getVulnerabilitiesStatistics() {
        return ResponseEntity.ok(statisticsService.getVulnerabilitiesStatistics());
    }

    @GetMapping("/configuration")
    public ResponseEntity<Map<String, Boolean>> getConfigurationStatistics() {
        return ResponseEntity.ok(statisticsService.getConfigurationStatistics());
    }

    @GetMapping("/recentFinishedScans")
    public ResponseEntity<Map<String, Object>> getRecentlyFinishedScans() {
        return ResponseEntity.ok(statisticsService.getRecentlyFinishedScans());
    }

    @GetMapping("/getWhoisInfo/{scanId}")
    public ResponseEntity<Map<String, String>> getWhoisInfo(@PathVariable Long scanId) {
        String domain = scanRepository.getOne(scanId).getScannedDomain();
        String whoisInfo = statisticsService.getWhoisDomainInfo(domain);
        Map<String, String> result = new HashMap<>();
        result.put("whois", whoisInfo);
        return ResponseEntity.ok(result);
    }
}
