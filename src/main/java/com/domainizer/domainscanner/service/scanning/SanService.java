package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SanService implements IDomainScanner {

    static Logger logger = LoggerFactory.getLogger(SanService.class);

    @Override
    public List<Domain> runScan(Scan s) {
        logger.info("Running SAN scan for domain " + s.getScannedDomain() + "(" + s.getName() + ")");
        return getDomainsCertInformation(s.getScannedDomain());
    }

    private List<Domain> getDomainsCertInformation(String domain) {
        // TODO prevent SSRF
        URL destinationURL = null;
        List<Domain> domains = new ArrayList<>();
        try {
            destinationURL = new URL("https://" + domain);
            HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
            conn.connect();
            Certificate[] certs = conn.getServerCertificates();
            for (Certificate cert : certs) {
                if (cert instanceof X509Certificate) {
                    X509Certificate xCert = (X509Certificate) cert;
                    if (xCert.getSubjectAlternativeNames() != null) {
                        // todo add to domain
                        domains.addAll(xCert.getSubjectAlternativeNames().stream().map(e -> new Domain(e.get(1).toString(), DomainSource.SAN, domain)).collect(Collectors.toList()));
                    }
                }
            }
        } catch (IOException | CertificateParsingException e) {
            logger.error("Exception while getting data from SAN certificate field for " + domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return domains;
    }
}
