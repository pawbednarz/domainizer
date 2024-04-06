package com.domainizer.domainscanner.controller;

import com.domainizer.domainscanner.model.config.AppConfig;
import com.domainizer.domainscanner.repository.config.AppConfigRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/config")
public class ConfigController {

    static Logger log = LoggerFactory.getLogger(ConfigController.class);

    AppConfigRepository appConfigRepository;

    public ConfigController(AppConfigRepository appConfigRepository) {
        this.appConfigRepository = appConfigRepository;
    }

    @GetMapping
    public ResponseEntity<AppConfig> getConfig() {
        AppConfig config = appConfigRepository.findById(1L).orElse(new AppConfig("", "", "", "", ""));
        return ResponseEntity.ok(config);
    }

    @PostMapping
    public ResponseEntity setConfig(@RequestBody AppConfig appConfig) {
        AppConfig oldConfig = appConfigRepository.findById(1L).orElse(new AppConfig("", "", "", "", ""));
        Map<String, String> errorResponse = new HashMap<>();
        // verify Virus Total key
        if (!appConfig.getVirusTotalKey().isEmpty() &&
                !appConfig.getVirusTotalKey().equals(oldConfig.getVirusTotalKey()) &&
                !checkVirusTotalApiKey(appConfig.getVirusTotalKey())) {
            errorResponse.put("virusTotal", "Invalid API key (403 response from Virus Total API)");
        }

        // verify Censys api parameters
        if (!appConfig.getCensysApiId().isEmpty() && !appConfig.getCensysApiSecret().isEmpty() &&
                !appConfig.getCensysApiId().equals(oldConfig.getCensysApiId()) &&
                !appConfig.getCensysApiSecret().equals(oldConfig.getCensysApiSecret()) &&
                !checkCensysApiKey(appConfig.getCensysApiId(), appConfig.getCensysApiSecret())
        ) {
            errorResponse.put("censys", "Invalid API parameters for Censys");
        }

        // verify Shodan api key
        if (!appConfig.getShodanApiSecret().isEmpty() &&
                !appConfig.getShodanApiSecret().equals(oldConfig.getShodanApiSecret()) &&
                !checkShodanApiKey(appConfig.getShodanApiSecret())) {
            errorResponse.put("shodan", "Invalid API key for Shodan");
        }

        // verify API Ninjas key
        if (!appConfig.getApiNinjasKey().isEmpty() &&
                !appConfig.getApiNinjasKey().equals(oldConfig.getApiNinjasKey()) &&
                !checkApiNinjasKey(appConfig.getApiNinjasKey())) {
            errorResponse.put("apiNinjas", "Invalid API key for API Ninjas");
        }

        // if there are errors, return them with 400 code
        if (errorResponse.size() > 0) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
        // else save new object and return 200 code
        appConfig.setId(1L);
        appConfigRepository.save(appConfig);
        return ResponseEntity.ok().build();
    }

    private boolean checkVirusTotalApiKey(String apiKey) {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + apiKey))
                .build();
        HttpResponse response = null;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.error("Error when testing connection to Virus Total with api key - " + e.getMessage());
            log.error(Arrays.toString(e.getStackTrace()));
        }
        return (response.statusCode() == 200);
    }

    private boolean checkCensysApiKey(String apiId, String apiSecret) {
        int arrLength = apiId.getBytes().length + ":".getBytes().length + apiSecret.getBytes().length;
        byte[] combined = new byte[arrLength];
        ByteBuffer buffer = ByteBuffer.wrap(combined);
        buffer.put(apiId.getBytes());
        buffer.put(":".getBytes());
        buffer.put(apiSecret.getBytes());
        combined = buffer.array();
        String authHeader = Base64.getEncoder().encodeToString(combined);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://search.censys.io/api/v2/hosts/search?q=facebook.com&per_page=1&virtual_hosts=EXCLUDE&sort=RELEVANCE"))
                .header("Accept", "application/json")
                .header("Authorization", "Basic " + authHeader)
                .build();
        HttpResponse response = null;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.error("Error when testing connection to Censys with api key - " + e.getMessage());
            log.error(Arrays.toString(e.getStackTrace()));
        }
        return (response.statusCode() == 200);
    }

    private boolean checkShodanApiKey(String apiKey) {
        //
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.shodan.io/dns/domain/facebook.com?key=" + apiKey))
                .build();
        HttpResponse response = null;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.error("Error when testing connection to Shodan with api key - " + e.getMessage());
            log.error(Arrays.toString(e.getStackTrace()));
        }
        return (response.statusCode() == 200);
    }

    private boolean checkApiNinjasKey(String apiKey) {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.api-ninjas.com/v1/whois?domain=facebook.com"))
                .header("X-Api-Key", apiKey)
                .build();
        HttpResponse response = null;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            log.error("Error when testing connection to Shodan with api key - " + e.getMessage());
            log.error(Arrays.toString(e.getStackTrace()));
        }
        return (response.statusCode() == 200);
    }
}
