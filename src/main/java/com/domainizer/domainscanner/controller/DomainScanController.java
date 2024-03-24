package com.domainizer.domainscanner.controller;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.RunScan;
import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.model.config.DomainScanConfig;
import com.domainizer.domainscanner.repository.DomainRepository;
import com.domainizer.domainscanner.repository.RunScanRepository;
import com.domainizer.domainscanner.repository.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/scan/{scanId}/domainScan")
public class DomainScanController {

    static Logger log = LoggerFactory.getLogger(DomainScanController.class);
    private final ScanRepository scanRepository;
    private final RunScanRepository runScanRepository;
    private final DomainRepository DomainRepository;

    @Autowired
    public DomainScanController(ScanRepository scanRepository,
                                RunScanRepository runScanRepository,
                                DomainRepository DomainRepository) {
        this.scanRepository = scanRepository;
        this.runScanRepository = runScanRepository;
        this.DomainRepository = DomainRepository;
    }

    @GetMapping("/config")
    public ResponseEntity<DomainScanConfig> getScanConfiguration(@PathVariable Long scanId) {
        DomainScanConfig domainScanConfig = scanRepository.findById(scanId).get().getDomainScanConfig();
        return ResponseEntity.ok(domainScanConfig);
    }

    // TODO do something like "getAllDiscoveredDomains

    @GetMapping("/results")
    public ResponseEntity<Map<String, Object>> getRunScansForScan(@PathVariable Long scanId) {
        Scan scan = scanRepository.findById(scanId).get();
        List<RunScan> runScans = runScanRepository.findByScanId(scanId);
        Map<String, Object> json = new HashMap<>();
        json.put("name", scan.getName());
        json.put("scannedDomain", scan.getScannedDomain());
        List<Map> runScanList = new ArrayList<>();
        runScans.forEach(el -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", el.getId());
            map.put("startDateTime", el.getStartDateTime());
            map.put("finishDateTime", el.getFinishDateTime());
            map.put("ipAddressCount", DomainRepository.getIpAddress(el));
            map.put("resultsCount", DomainRepository.countByRunScan(el));
            runScanList.add(map);
        });
        json.put("scanResults", runScanList);
        return ResponseEntity.ok(json);
    }

    @GetMapping("/results/{scanResultId}")
    public ResponseEntity<Map<String, Object>> getRunScan(@PathVariable Long scanId, @PathVariable Long scanResultId) {
        Scan scan = scanRepository.findById(scanId).get();
        Map<String, Object> json = new HashMap<>();
        List<Domain> domains = DomainRepository.findAllByRunScanId(scanResultId);
        json.put("id", scan.getId());
        json.put("name", scan.getName());
        json.put("scannedDomain", scan.getScannedDomain());
        json.put("results", domains);
        return ResponseEntity.ok(json);
    }
}
