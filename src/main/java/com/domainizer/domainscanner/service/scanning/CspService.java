package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CspService implements IDomainScanner {

    private static final Logger logger = LoggerFactory.getLogger(CspService.class);

    @Override
    public List<Domain> runScan(Scan s) {
        logger.info("Running Content Security Policy scan for domain " + s.getScannedDomain() + "(" + s.getName() + ")");
        return getCspDomains(s.getScannedDomain());
    }

    private List<Domain> getCspDomains(String domain) {
        HttpResponse response = makeHttpRequest(domain);
        String cspValue = response.headers().firstValue("Content-Security-Policy").orElse(null);
        List<Domain> domains = new ArrayList<>();
        if (cspValue != null) {
            String[] splitCspValues = cspValue.split(" ");
            domains.addAll(Arrays.stream(splitCspValues)
                    .filter(v -> v.endsWith(domain))
                    .map(v -> new Domain(v, DomainSource.CSP, domain))
                    .collect(Collectors.toList())
            );
        }
        return domains;
    }

    private HttpResponse makeHttpRequest(String domain) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://" + domain))
                .build();
        HttpResponse response = null;
        try {
            response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            logger.error("Error trying to get CSP header for domain - " + e.getMessage());
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return response;
    }
}
