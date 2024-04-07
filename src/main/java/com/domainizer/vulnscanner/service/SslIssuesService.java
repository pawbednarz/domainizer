package com.domainizer.vulnscanner.service;

import com.domainizer.vulnscanner.model.IpPortScanHelper;
import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.SecurityIssue;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SslIssuesService implements IVulnScanner {

    private static final Logger logger = LoggerFactory.getLogger(UnencryptedCommunicationService.class);

    @Override
    public List<SecurityIssue> runScan(List<IpPortScanHelper> ipPortScanHelperList) {
        List<String> ips = ipPortScanHelperList.stream().map(IpPortScanHelper::getIpAddress).collect(Collectors.toList());
        logger.info("Starting scan for ssl issues " + ips);
        return getSslIssues(ipPortScanHelperList);
    }

    private List<SecurityIssue> getSslIssues(List<IpPortScanHelper> portScanHelperList) {
        List<SecurityIssue> sslIssues = new ArrayList<>();
        portScanHelperList.forEach(hostData -> {
            List<OpenPort> openPort = hostData.getOpenPort().stream().filter(el -> el.getService().equals("HTTPS") || el.getOpenPort() == 8443 || el.getOpenPort() == 443).collect(Collectors.toList());

            hostData.getDomainNames().forEach(domainName -> openPort.forEach(port -> {
                try {
                    String resultFilename = getResultFilename(domainName, port.getOpenPort());
                    Runtime.getRuntime().exec("bash testssl.sh --json-pretty " + domainName + ":" + port.getOpenPort());
                    StringBuilder stringBuilder = new StringBuilder();
                    List<SslIssue> issues = parseJsonResults(resultFilename);
                    issues.forEach(el -> {
                        stringBuilder.append("Issue: ");
                        stringBuilder.append(el.name);
                        stringBuilder.append("\n Description: ");
                        stringBuilder.append(el.description);
                        stringBuilder.append("\n Severity: ");
                        stringBuilder.append(el.severity);
                        stringBuilder.append("\n");
                    });
                    sslIssues.add(new SecurityIssue("SSL/TLS issues", "Server SSL/TLS is not configured properly and might be potentially vulnerable to some" + "SSL/TLS attacks. Potential issues identified are: " + stringBuilder, domainName + ":" + port.getOpenPort(), getHighestSeverity(issues), port));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }));
        });
        return sslIssues;
    }

    private String getResultFilename(String domain, int port) {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd-HHmm");
        LocalDateTime now = LocalDateTime.now();
        return domain + "_p" + port + "-" + dtf.format(now) + ".json";
    }

    private List<SslIssue> parseJsonResults(String filename) {
        List<SslIssue> sslIssues = new ArrayList<>();
        JsonNode node;
        try {
            node = new ObjectMapper().readTree(new File(filename));
            JsonNode usedSslProtocols = node.get("scanResult").get("protocols");
            JsonNode sslVulnerabilities = node.get("scanResult").get("vulnerabilities");
            sslIssues.addAll(parseSingleJsonArray(usedSslProtocols));
            sslIssues.addAll(parseSingleJsonArray(sslVulnerabilities));
        } catch (IOException e) {
            logger.error("Exception while parsing JSON response from testssl.sh");
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return sslIssues;
    }

    private List<SslIssue> parseSingleJsonArray(JsonNode node) {
        List<SslIssue> sslIssues = new ArrayList<>();
        if (node.isArray()) {
            for (JsonNode findingNode : node) {
                if (!findingNode.get("severity").asText().equals("OK") || !findingNode.get("severity").asText().equals("INFO")) {
                    sslIssues.add(new SslIssue(findingNode.get("id").asText(), findingNode.get("severity").asText(), findingNode.get("finding").asText()));
                }
            }
        }
        return sslIssues;
    }

    private String getHighestSeverity(List<SslIssue> sslIssues) {
        List<String> severities = sslIssues.stream().map(el -> el.severity).collect(Collectors.toList());
        String result = "INFORMATIONAL";
        if (severities.contains("CRITICAL")) result = "CRITICAL";
        if (severities.contains("HIGH")) result = "HIGH";
        if (severities.contains("MEDIUM")) result = "MEDIUM";
        if (severities.contains("LOW")) result = "LOW";
        return result;
    }
}

class SslIssue {

    public String name;
    public String severity;
    public String description;

    public SslIssue(String name, String severity, String description) {
        this.name = name;
        this.severity = severity;
        this.description = description;
    }


}