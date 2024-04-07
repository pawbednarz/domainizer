package com.domainizer.domainscanner.service;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import com.domainizer.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.URL;
import java.security.SecureRandom;
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
        List<Domain> domains = new ArrayList<>();
        String cspValue = getCspValue(domain);
        if (cspValue != null && !cspValue.equals("")) {
            cspValue = cspValue.replace(";", "");
            String[] splitCspValues = cspValue.split(" ");
            domains.addAll(Arrays.stream(splitCspValues)
                    .filter(v -> v.endsWith(domain))
                    .filter(v -> !v.startsWith("*"))
                    .map(v -> new Domain(v, DomainSource.CSP, domain))
                    .collect(Collectors.toList())
            );
        }
        return domains;
    }

    private String getCspValue(String domain) {
        HttpsURLConnection conn = null;
        try {
            URL url = new URL("https://" + domain);
            conn = (HttpsURLConnection) url.openConnection();
            conn.setHostnameVerifier((s, sslSession) -> true);
            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(null, Utils.trustAllCerts, new SecureRandom());
            conn.setSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            logger.error("Error when trying to get CSP header from https://" + domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        String result = null;
        if (conn != null && conn.getHeaderFields() != null) {
            if (conn.getHeaderFields().containsKey("content-security-policy")) {
                result = conn.getHeaderField("content-security-policy");
            } else if (conn.getHeaderFields().containsKey("Content-Security-Policy")) {
                result = conn.getHeaderField("Content-Security-Policy");
            }
        }
        return result;
    }
}
