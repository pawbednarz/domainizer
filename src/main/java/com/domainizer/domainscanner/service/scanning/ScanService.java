package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.RunScan;
import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.repository.DomainRepository;
import com.domainizer.domainscanner.repository.RunScanRepository;
import com.domainizer.domainscanner.repository.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class ScanService {

    static Logger logger = LoggerFactory.getLogger(ScanService.class);
    private final ScanRepository scanRepository;
    private final CertTransparencyInfoService certTransparencyInfoService;
    private final ZoneTransferService zoneTransferService;
    private final SearchEngineService searchEngineService;
    private final SanService sanService;
    private final DnsRecordsService dnsRecordsService;
    private final DictionarySearchService dictionarySearchService;
    private final ApisService apisService;
    private final CspService cspService;
    private final RunScanRepository runScanRepository;
    private final DomainRepository DomainRepository;

    private final Map<String, Set<Domain>> tempDomains = new ConcurrentHashMap<>();

    public ScanService(ScanRepository scanRepository,
                       RunScanRepository runScanRepository,
                       CertTransparencyInfoService certTransparencyInfoService,
                       SanService sanService,
                       ZoneTransferService zoneTransferService,
                       SearchEngineService searchEngineService,
                       DnsRecordsService dnsRecordsService,
                       ApisService apisService,
                       CspService cspService,
                       DictionarySearchService dictionarySearchService,
                       DomainRepository DomainRepository) {
        this.scanRepository = scanRepository;
        this.runScanRepository = runScanRepository;
        this.sanService = sanService;
        this.certTransparencyInfoService = certTransparencyInfoService;
        this.zoneTransferService = zoneTransferService;
        this.searchEngineService = searchEngineService;
        this.dnsRecordsService = dnsRecordsService;
        this.apisService = apisService;
        this.cspService = cspService;
        this.dictionarySearchService = dictionarySearchService;
        this.DomainRepository = DomainRepository;
    }

    public void runScan(Long scanId) {
        Scan s = scanRepository.findById(scanId).get();
        RunScan runScan = initializeScanStart(s);
        startScan(s, runScan);
    }

    private void startScan(Scan s, RunScan runScan) {
        // create scanKey variable to be able to distinguish scans for the same domain at the same time
        String scanKey = s.getId() + "_" + runScan.getId();
        logger.info("Running scan for domain " + s.getScannedDomain() + ", scanKey=" + scanKey);
        List<IDomainScanner> domainScanners = getScannersBasedOnConfiguration(s);

        for (IDomainScanner scanner : domainScanners) {
            List<Domain> domains = scanner.runScan(s);
            domains.forEach(d -> d.setRunScan(runScan));
            updateScanCollections(domains, scanKey);
        }
        onScanFinish(s, runScan, scanKey);
        logger.info("Scan for domain " + s.getScannedDomain() + " has been finished");
    }

    private List<IDomainScanner> getScannersBasedOnConfiguration(Scan s) {
        List<IDomainScanner> domainScanners = new ArrayList<>();
        if (s.getDomainScanConfig().isCertificateTransparency()) domainScanners.add(certTransparencyInfoService);
        if (s.getDomainScanConfig().isDnsAggregators()) domainScanners.add(apisService);
        if (s.getDomainScanConfig().isDnsRecords()) domainScanners.add(dnsRecordsService);
        if (s.getDomainScanConfig().isSubjectAlternateName()) domainScanners.add(sanService);
        if (s.getDomainScanConfig().isSearchEngines()) domainScanners.add(searchEngineService);
        if (s.getDomainScanConfig().isZoneTransfer()) domainScanners.add(zoneTransferService);
        if (s.getDomainScanConfig().getDictionaryConfig().getDictionaryFile() != null)
            domainScanners.add(dictionarySearchService);
        if (s.getDomainScanConfig().isHttpHeaders()) domainScanners.add(cspService);
        return domainScanners;
    }

    private void updateScanCollections(List<Domain> domains, String scanKey) {
        // get set of domains which is up to date (could be updated by another scanning method)
        Set<Domain> domainSet = tempDomains.get(scanKey);
        // add all records to set
        domainSet.addAll(domains);
        // override old set with updated one
        tempDomains.put(scanKey, domainSet);
    }

    private RunScan initializeScanStart(Scan s) {
        s.setIsRunning(true);
        scanRepository.save(s);
        RunScan runScan = new RunScan(s);
        runScanRepository.save(runScan);
        String key = s.getId() + "_" + runScan.getId();

        tempDomains.put(key, new HashSet<>());
        return runScan;
    }

    private void onScanFinish(Scan s, RunScan runScan, String scanKey) {
        runScan.setFinishDateTime(LocalDateTime.now());
        runScanRepository.save(runScan);
        s.setIsRunning(false);
        scanRepository.save(s);
        Set<Domain> domainsSet = new HashSet<>(tempDomains.get(scanKey));
        List<Domain> domains = new ArrayList<>(domainsSet);
        DomainRepository.saveAll(domains
                .stream()
                .filter(val -> val.getName().endsWith(s.getScannedDomain()))
                .filter(val -> !val.getName().startsWith("*"))
                .filter(val -> !val.getName().equals(s.getScannedDomain()))
                .collect(Collectors.toList()));
        tempDomains.remove(scanKey);
    }
}
