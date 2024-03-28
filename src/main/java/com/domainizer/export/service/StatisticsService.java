package com.domainizer.export.service;

import com.domainizer.domainscanner.model.RunScan;
import com.domainizer.domainscanner.model.config.AppConfig;
import com.domainizer.domainscanner.repository.RunScanRepository;
import com.domainizer.domainscanner.repository.config.AppConfigRepository;
import com.domainizer.vulnscanner.model.RunVulnScan;
import com.domainizer.vulnscanner.repository.RunVulnScanRepository;
import com.domainizer.vulnscanner.repository.SecurityIssueRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class StatisticsService {

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
        AppConfig config = appConfigRepository.findById(1L).orElse(new AppConfig("", "", "", ""));
        Map<String, Boolean> configurationStatistics = new HashMap<>();

        configurationStatistics.put("virusTotal", !config.getVirusTotalKey().equals(""));
        configurationStatistics.put("censys", (!config.getCensysApiSecret().equals("") && !config.getCensysApiId().equals("")));
        configurationStatistics.put("shodan", !config.getShodanApiSecret().equals(""));

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
}
