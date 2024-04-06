package com.domainizer.export.service;

import com.domainizer.domainscanner.model.RunScan;
import com.domainizer.domainscanner.model.config.AppConfig;
import com.domainizer.domainscanner.repository.RunScanRepository;
import com.domainizer.domainscanner.repository.config.AppConfigRepository;
import com.domainizer.vulnscanner.model.RunVulnScan;
import com.domainizer.vulnscanner.repository.RunVulnScanRepository;
import com.domainizer.vulnscanner.repository.SecurityIssueRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;

@Service
public class StatisticsService {

    static Logger log = LoggerFactory.getLogger(StatisticsService.class);

    SecurityIssueRepository securityIssueRepository;
    AppConfigRepository appConfigRepository;
    RunScanRepository runScanRepository;
    RunVulnScanRepository runVulnScanRepository;

    @Autowired
    public StatisticsService(
            SecurityIssueRepository securityIssueRepository,
            AppConfigRepository appConfigRepository,
            RunScanRepository runScanRepository,
            RunVulnScanRepository runVulnScanRepository
    ) {
        this.securityIssueRepository = securityIssueRepository;
        this.appConfigRepository = appConfigRepository;
        this.runScanRepository = runScanRepository;
        this.runVulnScanRepository = runVulnScanRepository;
    }

    public Map<String, Integer> getVulnerabilitiesStatistics() {
        Map<String, Integer> vulnStats = new HashMap<>();

        int info = securityIssueRepository.countAllBySeverity("Informational");
        int low = securityIssueRepository.countAllBySeverity("Low");
        int medium = securityIssueRepository.countAllBySeverity("Medium");
        int high = securityIssueRepository.countAllBySeverity("Hugh");
        int critical = securityIssueRepository.countAllBySeverity("Critical");

        vulnStats.put("informational", info);
        vulnStats.put("low", low);
        vulnStats.put("medium", medium);
        vulnStats.put("high", high);
        vulnStats.put("critical", critical);

        return vulnStats;
    }

    public Map<String, Boolean> getConfigurationStatistics() {
        AppConfig config = appConfigRepository.findById(1L).orElse(new AppConfig("", "", "", "", ""));
        Map<String, Boolean> configurationStatistics = new HashMap<>();

        configurationStatistics.put("virusTotal", !config.getVirusTotalKey().equals(""));
        configurationStatistics.put("censys", (!config.getCensysApiSecret().equals("") && !config.getCensysApiId().equals("")));
        configurationStatistics.put("shodan", !config.getShodanApiSecret().equals(""));
        configurationStatistics.put("apiNinjas", !config.getApiNinjasKey().equals(""));

        return configurationStatistics;
    }

    public Map<String, Object> getRecentlyFinishedScans() {
        List<RunScan> runScanList = runScanRepository.findAll();
        List<RunVulnScan> runVulnScanList = runVulnScanRepository.findAll();

        runScanList.sort(Comparator.comparing(RunScan::getFinishDateTime));
        runVulnScanList.sort(Comparator.comparing(RunVulnScan::getFinishDateTime));

        Map<String, Object> jsonResponse = new HashMap<>();

        jsonResponse.put("recentRunScans", runScanList);
        jsonResponse.put("recentRunVulnScans", runVulnScanList);

        return jsonResponse;
    }

    public String getWhoisDomainInfo(String domain) {
        AppConfig config = appConfigRepository.findById(1L).orElse(new AppConfig("", "", "", "", ""));
        HttpResponse<String> response = null;
        if (!config.getApiNinjasKey().equals("")) {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.api-ninjas.com/v1/whois?domain=" + domain))
                    .header("X-Api-Key", config.getApiNinjasKey())
                    .build();
            try {
                response = client.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                log.error("Error when getting whois info from API Ninjas - " + e.getMessage());
                log.error(Arrays.toString(e.getStackTrace()));
            }
        }
        return response.body();
    }
}
