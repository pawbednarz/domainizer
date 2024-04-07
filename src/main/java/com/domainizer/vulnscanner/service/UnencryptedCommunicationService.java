package com.domainizer.vulnscanner.service;

import com.domainizer.vulnscanner.model.IpPortScanHelper;
import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.SecurityIssue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UnencryptedCommunicationService implements IVulnScanner {

    private static final Logger logger = LoggerFactory.getLogger(UnencryptedCommunicationService.class);

    @Override
    public List<SecurityIssue> runScan(List<IpPortScanHelper> ipPortScanHelperList) {
        List<String> ips = ipPortScanHelperList.stream().map(IpPortScanHelper::getIpAddress).collect(Collectors.toList());
        logger.info("Starting scan for unencrypted communication on " + ips);
        return getHttpServices(ipPortScanHelperList);
    }

    private List<SecurityIssue> getHttpServices(List<IpPortScanHelper> portScanHelperList) {
        List<SecurityIssue> securityIssues = new ArrayList<>();
        portScanHelperList.forEach(hostData -> {
            List<OpenPort> openPort = hostData
                    .getOpenPort()
                    .stream()
                    .filter(el -> el.getService().equals("HTTP"))
                    .collect(Collectors.toList());

            if (openPort.isEmpty()) {
                openPort = hostData
                        .getOpenPort()
                        .stream()
                        .filter(el -> el.getOpenPort() == 80 || el.getOpenPort() == 8080)
                        .collect(Collectors.toList());
            }

            List<OpenPort> finalOpenPort = openPort;
            hostData.getDomainNames().forEach(domainName -> finalOpenPort.forEach(port -> {
                if (isValidHttpService(domainName, port.getOpenPort())) {
                    securityIssues.add(new SecurityIssue(
                            "Unencrypted communication",
                            "There was HTTP service identified, which is not using SSL/TLS to encrypt " +
                                    "communication data. This can lead to man in the middle attack and potential " +
                                    "evasedroping of data.",
                            domainName + ":" + port.getOpenPort(),
                            "Low",
                            port
                    ));
                }
            }));
        });
        return securityIssues;
    }

    private boolean isValidHttpService(String address, int port) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://" + address + ":" + port))
                .method("GET", HttpRequest.BodyPublishers.noBody())
                .build();
        HttpClient httpClient = HttpClient
                .newBuilder()
                .build();
        boolean result = false;
        try {
            result = 0 < httpClient.send(request, HttpResponse.BodyHandlers.ofString()).statusCode();
        } catch (InterruptedException | IOException e) {
            logger.info("Error while executing isValidHttpService method for domain" + address + ":" + port);
            logger.info("Service might not be valid http service");
            logger.info(Arrays.toString(e.getStackTrace()));
        }
        return result;
    }
}
