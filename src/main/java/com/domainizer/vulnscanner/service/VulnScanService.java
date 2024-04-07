package com.domainizer.vulnscanner.service;

import com.domainizer.domainscanner.model.RunScan;
import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.repository.DomainRepository;
import com.domainizer.domainscanner.repository.RunScanRepository;
import com.domainizer.domainscanner.repository.ScanRepository;
import com.domainizer.vulnscanner.model.IpPortScanHelper;
import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.RunVulnScan;
import com.domainizer.vulnscanner.model.SecurityIssue;
import com.domainizer.vulnscanner.repository.OpenPortRepository;
import com.domainizer.vulnscanner.repository.RunVulnScanRepository;
import com.domainizer.vulnscanner.repository.SecurityIssueRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class VulnScanService {

    private static final Logger logger = LoggerFactory.getLogger(VulnScanService.class);

    private final ScanRepository scanRepository;
    private final RunScanRepository runScanRepository;
    private final RunVulnScanRepository runVulnScanRepository;
    private final PortScannerService portScannerService;
    private final DomainRepository DomainRepository;
    private final OpenPortRepository openPortRepository;
    private final HttpHeadersIssuesService httpHeadersIssuesService;
    private final WeakSSHCredentialsService weakSSHCredentialsService;
    private final SslIssuesService sslIssuesService;
    private final SecurityIssueRepository securityIssuesRepository;
    private final UnencryptedCommunicationService unencryptedCommunicationService;

    private final Map<String, Set<SecurityIssue>> tempSecurityIssues = new ConcurrentHashMap<>();

    public VulnScanService(ScanRepository scanRepository,
                           RunScanRepository runScanRepository,
                           RunVulnScanRepository runVulnScanRepository,
                           PortScannerService portScannerService,
                           DomainRepository DomainRepository,
                           HttpHeadersIssuesService httpHeadersIssuesService,
                           WeakSSHCredentialsService weakSSHCredentialsService,
                           OpenPortRepository openPortRepository,
                           UnencryptedCommunicationService unencryptedCommunicationService,
                           SslIssuesService sslIssuesService,
                           SecurityIssueRepository securityIssuesRepository) {
        this.scanRepository = scanRepository;
        this.runScanRepository = runScanRepository;
        this.runVulnScanRepository = runVulnScanRepository;
        this.portScannerService = portScannerService;
        this.DomainRepository = DomainRepository;
        this.httpHeadersIssuesService = httpHeadersIssuesService;
        this.weakSSHCredentialsService = weakSSHCredentialsService;
        this.openPortRepository = openPortRepository;
        this.sslIssuesService = sslIssuesService;
        this.unencryptedCommunicationService = unencryptedCommunicationService;
        this.securityIssuesRepository = securityIssuesRepository;
    }

    public void runVulnScan(Long scanId, Long runScanId) {
        RunScan runScan = runScanRepository.findById(runScanId).get();
        Scan scan = scanRepository.findById(scanId).get();
        RunVulnScan runVulnScan = initializeScanStart(scan, runScan);
        startScan(scan, runVulnScan, runScan);
    }

    private void startScan(Scan scan, RunVulnScan runVulnScan, RunScan runScan) {
        // create scanKey variable to be able to distinguish scans for the same domain at the same time
        String scanKey = scan.getId() + "_" + runVulnScan.getId();
        String portsToScan = scan.getVulnScanConfig().getScannedPorts();
        // scan for open ports on target
        List<String> ipAddresses = DomainRepository
                .findAllIpAddressByRunScanId(runScan)
                .stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        portScannerService.scanPortsForDomainScanResults(ipAddresses, portsToScan, runVulnScan);
        logger.info("Port scan finished");

        List<IpPortScanHelper> portScanDataList = new ArrayList<>();
        // for every address got from DB, create object with contain ipAddress, open ports for address and domains which resolve to that IP
        for (String ipAddress : ipAddresses) {
            List<OpenPort> ports = openPortRepository.findAllByRunVulnScanIdAndIpAddress(runVulnScan, ipAddress);
            if (!ports.isEmpty()) {
                portScanDataList.add(
                        new IpPortScanHelper(
                                ipAddress,
                                ports,
                                DomainRepository.findAllDomainsByRunScanIdAndIpAddress(runScan, ipAddress)
                        )
                );
            }
        }

        List<IVulnScanner> vulnScanners = getVulnScannersBasedOnConfiguration(scan);
        for (IVulnScanner scanner : vulnScanners) {
            List<SecurityIssue> issues = scanner.runScan(portScanDataList);
            updateScanCollection(issues, scanKey);
        }

        onScanFinish(scan, runVulnScan, scanKey);
        logger.info("Vulnerability scan for " + scan.getScannedDomain() + " finished");
    }

    private List<IVulnScanner> getVulnScannersBasedOnConfiguration(Scan s) {
        List<IVulnScanner> vulnScanners = new ArrayList<>();
        if (s.getVulnScanConfig().isSecurityHeaders()) vulnScanners.add(httpHeadersIssuesService);
        if (s.getVulnScanConfig().isWeakSshCredentials()) vulnScanners.add(weakSSHCredentialsService);
        if (s.getVulnScanConfig().isUnencryptedCommunication()) vulnScanners.add(unencryptedCommunicationService);
        if (s.getVulnScanConfig().isSslIssues()) vulnScanners.add(sslIssuesService);
        return vulnScanners;
    }

    private void updateScanCollection(List<SecurityIssue> issues, String scanKey) {
        // get set of issues which is up to date (could be updated by another scanning method)
        Set<SecurityIssue> issuesSet = tempSecurityIssues.get(scanKey);
        // add all records to set
        issuesSet.addAll(issues);
        // override old set with updated one
        tempSecurityIssues.put(scanKey, issuesSet);
    }

    private RunVulnScan initializeScanStart(Scan s, RunScan runScan) {
        s.setIsRunning(true);
        scanRepository.save(s);
        RunVulnScan runVulnScan = new RunVulnScan(runScan);
        runVulnScanRepository.save(runVulnScan);
        String key = s.getId() + "_" + runVulnScan.getId();

        tempSecurityIssues.put(key, new HashSet<>());
        return runVulnScan;
    }

    private void onScanFinish(Scan s, RunVulnScan runVulnScan, String scanKey) {
        runVulnScan.setFinishDateTime(LocalDateTime.now());
        runVulnScanRepository.save(runVulnScan);
        s.setIsRunning(false);
        scanRepository.save(s);

        List<SecurityIssue> issues = new ArrayList<>(tempSecurityIssues.get(scanKey));
        securityIssuesRepository.saveAll(issues);
    }
}

