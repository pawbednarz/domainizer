package com.domainizer.export.controller;

import com.domainizer.domainscanner.model.config.AppConfig;
import com.domainizer.domainscanner.repository.config.AppConfigRepository;
import com.domainizer.export.service.StatisticsService;
import com.domainizer.vulnscanner.repository.SecurityIssueRepository;
import com.jcraft.jsch.ConfigRepository;
import org.hibernate.engine.config.spi.ConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/statistics")
public class StatisticsController {

    StatisticsService statisticsService;

    @Autowired
    public StatisticsController(StatisticsService statisticsService) {
        this.statisticsService = statisticsService;
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
}
