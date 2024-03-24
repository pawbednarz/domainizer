package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class
SearchEngineService implements IDomainScanner {

    private static final Logger logger = LoggerFactory.getLogger(SearchEngineService.class);

    @Override
    public List<Domain> runScan(Scan s) {
        logger.info("Running Search Engine scan for domain " + s.getScannedDomain() + "(" + s.getName() + ")");
        return getDomainsGoogle(s.getScannedDomain());
    }

    private List<Domain> getDomainsGoogle(String domainName, int maxPage) {

        // TODO do something with bot protections (maybe throttle requests by a little)

        // multiply times 10, because thats what "start" paramater needs in google
        Set<String> domains = new HashSet<>();
        // get data from page 0 to maxPage from Google search engine
        for (int i = 0; i <= maxPage * 10; i += 10) {
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                logger.error(Arrays.toString(e.getStackTrace()));
            }

            // can throw HttpStatusException (429 code)
            Document doc = getSiteHTML("https://google.com/search?q=site:*." + domainName + "&start=" + i);

            // if doc is null then something went wrong - do not proceed
            if (doc == null) {
                logger.warn("Error when accessing Document object.");
                //TODO return message that something went wrong, maybe this is Too Many Requests HTTP response
                // but maybe it is not a good idea to place in inside of a loop?
                return null;
            }
            Elements domainsHTML = doc.select("cite.iUh30.Zu0yb.tjvcx");
            // after every data retrieval, add scrapped domains to "domains" list
            domains.addAll(domainsHTML
                    .stream()
                    .map(e -> e.ownText().split("/")[2])
                    .collect(Collectors.toSet()));
        }

        return domains
                .stream()
                .filter(e -> !e.equals(domainName))
                .map(e -> new Domain(e, DomainSource.SEARCH_ENG_GOOGLE, domainName))
                .collect(Collectors.toList());
    }

    public List<Domain> getDomainsGoogle(String domainName) {
        return getDomainsGoogle(domainName, 10);
    }

    private Document getSiteHTML(String address) {
        try {
            Connection conn = Jsoup.connect(address);
            return conn.get();
        } catch (IOException e) {
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return null;
    }
}
