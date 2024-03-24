package com.domainizer.vulnscanner.controller;

import com.domainizer.domainscanner.model.RunScan;
import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.repository.DomainRepository;
import com.domainizer.domainscanner.repository.RunScanRepository;
import com.domainizer.domainscanner.repository.ScanRepository;
import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.IpPortScanHelper;
import com.domainizer.vulnscanner.model.RunVulnScan;
import com.domainizer.vulnscanner.model.SecurityIssue;
import com.domainizer.vulnscanner.repository.OpenPortRepository;
import com.domainizer.vulnscanner.repository.RunVulnScanRepository;
import com.domainizer.vulnscanner.service.scanner.VulnScanService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/scan/{scanId}/vulnScan")
public class VulnScanController {

    private final VulnScanService vulnScanService;
    private final ScanRepository scanRepository;
    private final RunVulnScanRepository runVulnScanRepository;
    private final OpenPortRepository openPortRepository;
    private final DomainRepository DomainRepository;
    private final RunScanRepository runScanRepository;

    @Autowired
    public VulnScanController(
            VulnScanService vulnScanService,
            ScanRepository scanRepository,
            RunVulnScanRepository runVulnScanRepository,
            OpenPortRepository openPortRepository,
            DomainRepository DomainRepository,
            RunScanRepository runScanRepository) {
        this.vulnScanService = vulnScanService;
        this.scanRepository = scanRepository;
        this.runVulnScanRepository = runVulnScanRepository;
        this.openPortRepository = openPortRepository;
        this.DomainRepository = DomainRepository;
        this.runScanRepository = runScanRepository;
    }

    @PostMapping("/run")
    public ResponseEntity runVulnScan(@RequestBody Map<String, Long> scanIdMap) {
        Long scanId = scanIdMap.get("scanId");
        Long runScanId = scanIdMap.get("runScanId");
        this.vulnScanService.runVulnScan(scanId, runScanId);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/results/{runScanId}")
    public ResponseEntity getRunScansForScan(@PathVariable Long scanId, @PathVariable Long runScanId) {
        Scan scan = scanRepository.findById(scanId).get();
        List<RunVulnScan> runVulnScans = runVulnScanRepository.findByRunScanId(runScanId);

        Map<String, Object> json = new HashMap<>();
        json.put("name", scan.getName());
        json.put("scannedDomain", scan.getScannedDomain());
        List<Map> runVulnScanList = new ArrayList<>();

        runVulnScans.forEach(el -> {
            List<OpenPort> openPorts = openPortRepository.findAllByRunVulnScan(el);
            int securityIssueCount = 0;
            for (OpenPort port : openPorts) {
                securityIssueCount += port.getSecurityIssue().size();
            }
            int finalSecurityIssueCount = securityIssueCount;
            Map<String, Object> map = new HashMap<>();
            map.put("id", el.getId());
            map.put("startDateTime", el.getStartDateTime());
            map.put("finishDateTime", el.getFinishDateTime());
            map.put("openPortsCount", openPorts.size());
            map.put("issuesCount", finalSecurityIssueCount);
            runVulnScanList.add(map);
        });
        json.put("results", runVulnScanList);
        return ResponseEntity.ok(json);
    }

    @GetMapping("/results/{runScanId}/{vulnScanResultId}")
    public ResponseEntity getRunVulnScan(@PathVariable Long scanId, @PathVariable Long runScanId, @PathVariable Long vulnScanResultId) {
        // TODO implement function in a way that it will return {ipaddredss X, openports: {x,x,x,x}, domains:{x,x,x,x}, and again ipaddress etc}
        Scan scan = scanRepository.findById(scanId).get();
        RunScan runScan = runScanRepository.findById(runScanId).get();
        List<String> ipAddresses = DomainRepository
                .findAllIpAddressByRunScanId(runScan)
                .stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        RunVulnScan runVulnScan = runVulnScanRepository.findById(vulnScanResultId).get();

        List<IpPortScanHelper> portScanDataList = new ArrayList<>();
        // for every address got from DB, create object with contain ipAddress, open ports for address and domains which resolve to that IP
        for (String ipAddress : ipAddresses) {
            portScanDataList.add(
                    new IpPortScanHelper(
                            ipAddress,
                            openPortRepository.findAllByRunVulnScanIdAndIpAddress(runVulnScan, ipAddress),
                            DomainRepository.findAllDomainsByRunScanIdAndIpAddress(runScan, ipAddress)
                    )
            );
        }
        Map<String, Object> json = new HashMap<>();
        json.put("id", scan.getId());
        json.put("name", scan.getName());
        json.put("scannedDomain", scan.getScannedDomain());
        json.put("results", portScanDataList);
        return ResponseEntity.ok(json);
    }

    @GetMapping("/results/{runScanId}/{vulnScanResultId}/issues")
    public ResponseEntity getRunVulnScanSecurityIssues(@PathVariable Long scanId, @PathVariable Long runScanId, @PathVariable Long vulnScanResultId) {
        // TODO implement function in a way that it will return {ipaddredss X, openports: {x,x,x,x}, domains:{x,x,x,x}, and again ipaddress etc}
        Scan scan = scanRepository.findById(scanId).get();
        List<OpenPort> openPorts = openPortRepository.findAllByRunVulnScanId(vulnScanResultId);
        List<SecurityIssue> securityIssues = new ArrayList<>();
        for (OpenPort port : openPorts) {
            if (!port.getSecurityIssue().isEmpty()) {
                securityIssues.addAll(port.getSecurityIssue());
            }
        }
        Map<String, Object> json = new HashMap<>();
        json.put("id", scan.getId());
        json.put("name", scan.getName());
        json.put("scannedDomain", scan.getScannedDomain());
        json.put("results", securityIssues);
        return ResponseEntity.ok(json);
    }
}
