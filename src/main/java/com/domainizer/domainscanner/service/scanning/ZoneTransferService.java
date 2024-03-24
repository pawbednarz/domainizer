package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.xbill.DNS.*;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class ZoneTransferService implements IDomainScanner {

    static Logger logger = LoggerFactory.getLogger(ZoneTransferService.class);

    @Override
    public List<Domain> runScan(Scan s) {
        logger.info("Running Zone Transfer scan for domain " + s.getScannedDomain() + "(" + s.getName() + ")");
        return performZoneTransfer(s.getScannedDomain());
    }

    private List<Domain> performZoneTransfer(String domain) {
        List<String> nameservers = getNameServersForDomain(domain);
        Set<Domain> zoneTransferDomains = new HashSet<>();
        for (Object ns : nameservers) {
            zoneTransferDomains.addAll(performZoneTransferSingleDomain(domain, (String) ns));
        }
        return new ArrayList<>(zoneTransferDomains);
    }

    private List<Domain> performZoneTransferSingleDomain(String domain, String nameserver) {
        List<String> zoneTransferResults = new ArrayList<>();
        try {
            ZoneTransferIn xfr = ZoneTransferIn.newAXFR(Name.fromString(domain), nameserver, null);
            xfr.run();
            for (Record r : xfr.getAXFR()) {
                zoneTransferResults.add(r.toString());
            }
        } catch (Exception e) {
            logger.error("Exception while performing Zone transfer for " + domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return parseZoneTransferResults(zoneTransferResults, domain);
    }

    private List<Domain> parseZoneTransferResults(List<String> zoneTransferData, String domain) {
        return zoneTransferData.stream()
                .filter(el -> !el.startsWith(domain))
                .map(el -> el.split(domain)[0])
                .map(el -> el + domain)
                .map(el -> new Domain(el, DomainSource.ZONE_TRANSFER, domain))
                .collect(Collectors.toList());
    }

    private List<String> getNameServersForDomain(String domain) {
        Record[] records = null;
        try {
            records = new Lookup(domain, Type.NS).run();
        } catch (TextParseException e) {
            logger.error("Text Parse Excetion during Zone Transfer- " + e.getMessage());
            logger.error(Arrays.toString(e.getStackTrace()));
        }

        List<String> nsRecords = new ArrayList<>();
        for (Record r : records) {
            NSRecord ns = (NSRecord) r;
            nsRecords.add(ns.getTarget().toString());
        }
        return nsRecords;
    }
}
