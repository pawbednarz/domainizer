package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class DictionarySearchService implements IDomainScanner {

    static Logger logger = LoggerFactory.getLogger(DictionarySearchService.class);

    @Override
    public List<Domain> runScan(Scan s) {
        logger.info("Running Dictionary Search scan for domain " + s.getScannedDomain() + "(" + s.getName() + ")");
        File wordlist = new File("dictionaryFiles/" + s.getDomainScanConfig().getDictionaryConfig().getDictionaryFile());
        return performDictionaryEnumeration(s.getScannedDomain(), wordlist);
    }

    private List<Domain> performDictionaryEnumeration(String domain, File wordlist) {
        /* TODO find a way to clear data gathered from cert transparency by dictionary identification - cert transparency
           data might be outdated while dictionary is up to date
           TODO something is not working right here - false positives in scans
        */
        List<Domain> domains = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(wordlist))) {
            for (String word = br.readLine(); word != null; word = br.readLine()) {
                if (subdomainExists(word, domain)) {
                    domains.add(new Domain(word + "." + domain, DomainSource.DICTIONARY, domain));
                }
            }
        } catch (IOException e) {
            logger.error("Exception while running dictionary discovery against {0}", domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return domains;
    }

    private boolean subdomainExists(String subdomain, String domain) {
        try {
            Record[] rs = new Lookup(subdomain + "." + domain, Type.A).run();
            if (rs == null) {
                // subdomain does not exist
                return false;
            }
        } catch (TextParseException e) {
            logger.error("Error while running dictionary discovery against {0}", domain);
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        // subdomain does exist
        return true;
    }
}
