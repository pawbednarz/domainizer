package com.domainizer.domainscanner.service;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class DnsRecordsService implements IDomainScanner {

    static Logger logger = LoggerFactory.getLogger(DnsRecordsService.class);

    // declare array of record types to iterate over it later to get all the records information
    private final int[] recordTypes = new int[]{
            Type.A,
            Type.AAAA,
            Type.CNAME,
            Type.MX,
            Type.NS,
            Type.SOA
    };

    @Override
    public List<Domain> runScan(Scan s) {
        logger.info("Running DNS Record scan for domain " + s.getScannedDomain() + "(" + s.getName() + ")");
        return getDomainsFromDNSRecords(s.getScannedDomain());
    }

    private List<Domain> getDomainsFromDNSRecords(String domain) {
        List<Record> rs = getRecordsData(domain);
        List<String> domainNames = processRecordsIntoDomainNames(rs).stream().filter(x -> x.endsWith(domain)).collect(Collectors.toList());
        return domainNames.stream().map(name -> new Domain(name, DomainSource.DNS_RECORD, domain)).collect(Collectors.toList());
    }

    private List<Record> getRecordsData(String domain) {
        List<Record> rs = new ArrayList<>();
        try {
            Record[] temp;
            for (int type : recordTypes) {
                // some records might return no data - "temp" array is to get result of lookup and check if it is null
                temp = new Lookup(domain, type).run();
                if (temp != null) {
                    rs.addAll(Arrays.stream(temp).collect(Collectors.toList()));
                }
            }
        } catch (TextParseException e) {
            logger.error("Exception when getting subdomain data from DNS records");
            logger.error(Arrays.toString(e.getStackTrace()));
            throw new RuntimeException(e);
        }
        return rs;
    }

    private List<String> processRecordsIntoDomainNames(List<Record> rs) {
        List<String> domainNames = new ArrayList<>();
        for (Record r : rs) {
            // get domains form records and add to domainNames list
            if (r.getAdditionalName() != null) {
                domainNames.add(r.getAdditionalName().toString(true));
            }
            // this if statement is specially for SOA records - it has mehtod getAdmin() which also can hold a domain name
            if (r instanceof SOARecord && ((SOARecord) r).getAdmin() != null) {
                domainNames.add(((SOARecord) r).getAdmin().toString(true));
            }
        }
        return domainNames;
    }

}
