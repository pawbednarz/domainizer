package com.domainizer.domainscanner.controller;

import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.repository.ScanRepository;
import com.domainizer.domainscanner.service.scanning.ScanService;
import com.domainizer.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/scan")
public class ScanController {

    static Logger log = LoggerFactory.getLogger(ScanController.class);
    private final ScanRepository scanRepository;
    private final ScanService scanService;

    @Autowired
    public ScanController(ScanRepository scanRepository,
                          ScanService scanService) {
        this.scanRepository = scanRepository;
        this.scanService = scanService;
    }

    @GetMapping
    public ResponseEntity<List<Scan>> getScans(@RequestParam @Nullable Integer records) {
        if (records != null) {
            Page<Scan> page = scanRepository.findAll(PageRequest.of(0, records, Sort.by(Sort.Direction.DESC, "id")));
            return ResponseEntity.ok(page.get().collect(Collectors.toList()));
        }
        List<Scan> scans = scanRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));
        return ResponseEntity.ok(scans);
    }

    @GetMapping("/{scanId}")
    public ResponseEntity<Scan> getScan(@PathVariable Long scanId) {
        Scan scan = scanRepository.findById(scanId).get();
        return ResponseEntity.ok(scan);
    }

    // TODO think about parsing binding results and returning message with errors to user
    @PostMapping("/addScan")
    public ResponseEntity<Scan> addScan(@Valid @RequestBody Scan newScan) {
        if (newScan.getDomainScanConfig().getDictionaryConfig().getDictionaryFile() != null) {
            String fileName = Utils.generateFileName();
            String fileData = newScan.getDomainScanConfig().getDictionaryConfig().getDictionaryFile();
            newScan.getDomainScanConfig().getDictionaryConfig().setDictionaryFile(fileName);
            Utils.saveDictionaryFileToDisk(fileData, fileName);
        }
        scanRepository.save(newScan);
        log.info("New scan {} created for {}", newScan.getName(), newScan.getScannedDomain());
        return ResponseEntity.ok(scanRepository.save(newScan));
    }

    @PostMapping(value = "/run")
    public ResponseEntity<Void> runScan(@RequestBody Map<String, Long> scanIdMap) {
        Long scanId = scanIdMap.get("scanId");
        this.scanService.runScan(scanId);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> deleteScan(@RequestBody Map<String, Object> scanIdMap) {
        if (scanIdMap.containsKey("scanId")) {
            Long scanId = (long) (int) scanIdMap.get("scanId");
            scanRepository.deleteById(scanId);
        }
        return ResponseEntity.ok().build();
    }
}