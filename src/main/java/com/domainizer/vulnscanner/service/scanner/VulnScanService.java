package com.domainizer.vulnscanner.service.scanner;

import com.domainizer.domainscanner.model.RunScan;
import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.repository.DomainRepository;
import com.domainizer.domainscanner.repository.RunScanRepository;
import com.domainizer.domainscanner.repository.ScanRepository;
import com.domainizer.vulnscanner.model.IpPortScanHelper;
import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.SecurityIssue;
import com.domainizer.vulnscanner.repository.OpenPortRepository;
import com.domainizer.vulnscanner.repository.RunVulnScanRepository;
import com.domainizer.vulnscanner.repository.SecurityIssueRepository;
import com.domainizer.vulnscanner.service.PortScannerService;
import com.domainizer.vulnscanner.model.RunVulnScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
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
    private final SecurityIssueRepository securityIssuesRepository;

    private final UnencryptedCommunicationService unencryptedCommunicationService;

    public VulnScanService(ScanRepository scanRepository,
                           RunScanRepository runScanRepository,
                           RunVulnScanRepository runVulnScanRepository,
                           PortScannerService portScannerService,
                           DomainRepository DomainRepository,
                           HttpHeadersIssuesService httpHeadersIssuesService,
                           WeakSSHCredentialsService weakSSHCredentialsService,
                           OpenPortRepository openPortRepository,
                           UnencryptedCommunicationService unencryptedCommunicationService,
                           SecurityIssueRepository securityIssuesRepository) {
        this.scanRepository = scanRepository;
        this.runScanRepository = runScanRepository;
        this.runVulnScanRepository = runVulnScanRepository;
        this.portScannerService = portScannerService;
        this.DomainRepository = DomainRepository;
        this.httpHeadersIssuesService = httpHeadersIssuesService;
        this.weakSSHCredentialsService = weakSSHCredentialsService;
        this.openPortRepository = openPortRepository;
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
            List<OpenPort> op = openPortRepository.findAllByRunVulnScanIdAndIpAddress(runVulnScan, ipAddress);
            if (!op.isEmpty()) {
                portScanDataList.add(
                        new IpPortScanHelper(
                                ipAddress,
                                op,
                                DomainRepository.findAllDomainsByRunScanIdAndIpAddress(runScan, ipAddress)
                        )
                );
            }
        }

        List<SecurityIssue> securityIssues = new ArrayList<>();
        List<IVulnScanner> vulnScanners = getVulnScannersBasedOnConfiguration(scan);
        for (IVulnScanner scanner : vulnScanners) {
            securityIssues.addAll(scanner.runScan(portScanDataList));
        }

        securityIssuesRepository.saveAll(securityIssues);
        System.out.println(securityIssues);
        logger.info("Vulnerability scan for " + scan.getScannedDomain() + " finished");
    }

    private List<IVulnScanner> getVulnScannersBasedOnConfiguration(Scan s) {
        List<IVulnScanner> vulnScanners = new ArrayList<>();
        if (s.getVulnScanConfig().isSecurityHeaders()) vulnScanners.add(httpHeadersIssuesService);
        //if (s.getVulnScanConfig().isWeakSshCredentials()) vulnScanners.add(weakSSHCredentialsService);
        if (s.getVulnScanConfig().isUnencryptedCommunication()) vulnScanners.add(unencryptedCommunicationService);
//        if (s.getVulnScanConfig().isSslIssues()) vulnScanners.add(SslIssuesService);
        return vulnScanners;
    }

    private RunVulnScan initializeScanStart(Scan s, RunScan runScan) {
        //s.setIsRunning(true);
        //scanRepository.save(s);
        RunVulnScan runVulnScan = new RunVulnScan(runScan);
        runVulnScanRepository.save(runVulnScan);
        //String key = s.getId() + "_" + runVulnScan.getId();
        return runVulnScan;
    }
}

