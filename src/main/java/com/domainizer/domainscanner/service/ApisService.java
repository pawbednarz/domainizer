package com.domainizer.domainscanner.service;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.model.config.AppConfig;
import com.domainizer.domainscanner.repository.config.AppConfigRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.*;

@Service
public class ApisService implements IDomainScanner {

    static Logger logger = LoggerFactory.getLogger(ApisService.class);
    @Autowired
    AppConfigRepository appConfigRepository;

    @Override
    public List<Domain> runScan(Scan s) {
        logger.info("Running API scan for domain " + s.getScannedDomain() + "(" + s.getName() + ")");
        return getDomainsVirusTotal(s.getScannedDomain());
    }

    private List<Domain> getDomainsVirusTotal(String domain) {
        List<AppConfig> appConfigList = appConfigRepository.findAll();
        if (appConfigList.isEmpty()) {
            logger.info("No api keys for API scanning found");
            return Collections.emptyList();
        }
        AppConfig appConfig = appConfigList.get(0);
        String virusTotalApiKey = appConfig.getVirusTotalKey();
        String censysApiId = appConfig.getCensysApiId();
        String censysApiSecret = appConfig.getCensysApiSecret();
        String shodanApiSecret = appConfig.getShodanApiSecret();

        ArrayList<Domain> domains = new ArrayList<>();
        if (!virusTotalApiKey.isEmpty()) {
            domains.addAll(getSubdomainsFromVirusTotal(domain, virusTotalApiKey));
        }

//        if (!censysApiId.isEmpty() && !censysApiSecret.isEmpty()) {
//            domains.addAll(getSubdomainsFromCensys(censysApiId, censysApiSecret, domain));
//        }

        if (!shodanApiSecret.isEmpty()) {
            domains.addAll(getSubdomainsFromShodan(domain, shodanApiSecret));
        }

        return domains;
    }

    private List<Domain> getSubdomainsFromVirusTotal(String domain, String apiKey) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/api/v3/domains/" + domain + "/subdomains?limit=1000"))
                .header("X-Apikey", apiKey)
                .method("GET", HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<String> response = null;
        try {
            response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            logger.error("Exception while getting subdomains from VirusTotal API for" + domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }

        JsonNode node = null;
        try {
            node = new ObjectMapper().readTree(response.body());
        } catch (JsonProcessingException e) {
            logger.error("Exception while parsing JSON from VirusTotal API for" + domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        int domainsNum = node.get("data").size();
        List<Domain> domains = new ArrayList<>();
        for (int i = 0; i < domainsNum; i++) {
            String domainName = node.get("data").get(i).get("id").asText();
            domains.add(new Domain(domainName, DomainSource.API_VIRUS_TOTAL, domain));
        }
        return domains;
    }

    private List<Domain> getSubdomainsFromCensys(String apiId, String apiSecret, String domain) {
        int arrLength = apiId.getBytes().length + ":".getBytes().length + apiSecret.getBytes().length;
        byte[] combined = new byte[arrLength];
        ByteBuffer buffer = ByteBuffer.wrap(combined);
        buffer.put(apiId.getBytes());
        buffer.put(":".getBytes());
        buffer.put(apiSecret.getBytes());
        combined = buffer.array();
        String authHeader = Base64.getEncoder().encodeToString(combined);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://search.censys.io/api/v2/hosts/search?q=" + domain + "&per_page=1&virtual_hosts=EXCLUDE&sort=RELEVANCE"))
                .header("Accept", "application/json")
                .header("Authorization", "Basic " + authHeader)
                .build();
        HttpResponse<String> response = null;
        try {
            response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            logger.error("Error when testing connection to Censys with api key - " + e.getMessage());
            logger.error(Arrays.toString(e.getStackTrace()));
        }

        JsonNode node = null;
        try {
            node = new ObjectMapper().readTree(response.body()).get("result").get("hits");
        } catch (JsonProcessingException e) {
            logger.error("Exception while parsing JSON from Censys API for" + domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }

        List<Domain> domains = new ArrayList<>();
        if (node.isArray()) {
            for (JsonNode hitsNode : node) {
                for (JsonNode innerNode : hitsNode) {
                    JsonNode subdomainNode = innerNode.get("reverse_dns").get("names");
                    for (JsonNode subdomain : subdomainNode) {
                        System.out.println(subdomain);
                        domains.add(new Domain(subdomain.toString(), DomainSource.API_VIRUS_TOTAL, domain));
                    }
                }
            }
        }
        return domains;
    }

    private List<Domain> getSubdomainsFromShodan(String domain, String apiKey) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.shodan.io/dns/domain/" + domain + "?key=" + apiKey))
                .method("GET", HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<String> response = null;
        try {
            response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            logger.error("Exception while getting subdomains from Shodan API for" + domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }

        JsonNode node = null;
        try {
            node = new ObjectMapper().readTree(response.body()).get("subdomains");
        } catch (JsonProcessingException e) {
            logger.error("Exception while parsing JSON from Shodan API for" + domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }

        List<Domain> domains = new ArrayList<>();
        if (node.isArray()) {
            for (JsonNode subdomainNode : node) {
                String subdomain = subdomainNode.asText().replace("\"", "");
                domains.add(new Domain(subdomain + "." + domain, DomainSource.API_VIRUS_TOTAL, domain));
            }
        }
        return domains;
    }
}
