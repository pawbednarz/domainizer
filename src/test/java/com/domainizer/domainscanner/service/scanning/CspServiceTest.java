package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.model.config.DomainScanConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;

@SpringBootTest
class CspServiceTest {

    @Autowired
    CspService cspService;

    @Test
    void testRunScan_isAbleToParseCSP() {
        Scan s = new Scan("test", "dietmaxpol.pl", new DomainScanConfig());
        List<Domain> foundDomains = cspService.runScan(s);

        Assertions.assertNotEquals(0, foundDomains.size());
    }

    @Test
    void testRunScan_returnsValidResult() {
        Scan s = new Scan("test", "dietmaxpol.pl", new DomainScanConfig());
        List<Domain> foundDomains = cspService.runScan(s);
        List<Domain> expectedDomains = new ArrayList<>();
        expectedDomains.add(new Domain("test.dietmaxpol.pl", DomainSource.CSP, "dietmaxpol.pl"));
        expectedDomains.add(new Domain("internal.dietmaxpol.pl", DomainSource.CSP, "dietmaxpol.pl"));
        expectedDomains.add(new Domain("admin.dietmaxpol.pl", DomainSource.CSP, "dietmaxpol.pl"));

        Assertions.assertIterableEquals(expectedDomains, foundDomains);
    }
}