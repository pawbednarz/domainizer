package com.domainizer.export.controller;

import com.domainizer.domainscanner.repository.DomainRepository;
import com.domainizer.export.service.ExportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;

@RestController
@RequestMapping("/export")
public class ExportController {

    ExportService exportService;
    DomainRepository domainRepository;

    @Autowired
    public ExportController(ExportService exportService, DomainRepository domainRepository) {
        this.exportService = exportService;
        this.domainRepository = domainRepository;
    }

    @GetMapping("/domain/{runScanId}")
    public ResponseEntity exportDomains(@PathVariable Long runScanId, @RequestParam String type) {
        String filename = "domainExport_" + runScanId;
        String content = "";
        switch (type) {

            case "txt":
                filename += ".txt";
                content = exportService.exportDomainsToTxt(runScanId);
                return ResponseEntity
                        .ok()
                        .headers(getFileDownloadHttpHeaders(content.length(), filename, "plain/text"))
                        .body(content);

            case "pdf":
                filename += ".pdf";
                ByteArrayInputStream bis = exportService.exportDomainsToPdf(runScanId);
                return ResponseEntity
                        .ok()
                        .headers(getFileDownloadHttpHeaders(bis.available(), filename, "application/pdf"))
                        .body(new InputStreamResource(bis));

            case "csv":
                filename += ".csv";
                content = exportService.exportDomainsToCsv(runScanId);
                return ResponseEntity
                        .ok()
                        .headers(getFileDownloadHttpHeaders(content.length(), filename, "text/csv"))
                        .body(content);

            default:
                return ResponseEntity.badRequest().body("{\"error\":\"Wrong export file type provided - must be one of txt, pdf, csv.\"}");
        }
    }

    private HttpHeaders getFileDownloadHttpHeaders(int contentLength, String filename, String contentType) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, contentType);
        headers.add(HttpHeaders.CONTENT_LENGTH, String.valueOf(contentLength));
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"");
        return headers;
    }
}
