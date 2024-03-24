package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.DomainSource;
import com.domainizer.domainscanner.model.Scan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CertTransparencyInfoService implements IDomainScanner {

    private static final Logger logger = LoggerFactory.getLogger(CertTransparencyInfoService.class);

    @Override
    public List<Domain> runScan(Scan s) {
        logger.info("Running Certificate Transparency scan for domain " + s.getScannedDomain() + "(" + s.getName() + ")");
        return getSubdomainsDB(s.getScannedDomain());
    }

    private List<Domain> getSubdomainsDB(String domain) {
        // TODO add some validation?
        try {
            // TODO REMOVE EXPIRED CERTIFICATES!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            final String stmt = "WITH ci AS (\n" +
                    "    SELECT min(sub.CERTIFICATE_ID) ID,\n" +
                    "           min(sub.ISSUER_CA_ID) ISSUER_CA_ID,\n" +
                    "           array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,\n" +
                    "           x509_commonName(sub.CERTIFICATE) COMMON_NAME,\n" +
                    "           x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,\n" +
                    "           x509_notAfter(sub.CERTIFICATE) NOT_AFTER,\n" +
                    "           encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER\n" +
                    "        FROM (SELECT *\n" +
                    "                  FROM certificate_and_identities cai\n" +
                    "                  WHERE plainto_tsquery('certwatch', ?) @@ identities(cai.CERTIFICATE)\n" +
                    "                      AND cai.NAME_VALUE ILIKE ('%' || ? || '%')\n" +
                    "                  LIMIT 10000\n" +
                    "             ) sub\n" +
                    "        GROUP BY sub.CERTIFICATE\n" +
                    ")\n" +
                    "SELECT ci.ISSUER_CA_ID,\n" +
                    "        ca.NAME ISSUER_NAME,\n" +
                    "        ci.COMMON_NAME,\n" +
                    "        ci.NAME_VALUES NAME_VALUE,\n" +
                    "        ci.ID ID,\n" +
                    "        le.ENTRY_TIMESTAMP,\n" +
                    "        ci.NOT_BEFORE,\n" +
                    "        ci.NOT_AFTER,\n" +
                    "        ci.SERIAL_NUMBER\n" +
                    "    FROM ci\n" +
                    "            LEFT JOIN LATERAL (\n" +
                    "                SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP\n" +
                    "                    FROM ct_log_entry ctle\n" +
                    "                    WHERE ctle.CERTIFICATE_ID = ci.ID\n" +
                    "            ) le ON TRUE,\n" +
                    "         ca\n" +
                    "    WHERE ci.ISSUER_CA_ID = ca.ID\n" +
                    "    ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;";

            final String CRT_SH_DATABASE_URL = "jdbc:postgresql://crt.sh/certwatch?user=guest";
            // TODO use try-catch
            Connection conn = DriverManager.getConnection(CRT_SH_DATABASE_URL);
            PreparedStatement ps = conn.prepareStatement(stmt);
            ps.setString(1, domain);
            ps.setString(2, domain);
            ResultSet results = ps.executeQuery();
            conn.close();

            return processSQLData(results, domain);
        } catch (SQLException e) {
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return new ArrayList<>();
    }

    private List<Domain> processSQLData(ResultSet sqlData, String domain) {
        List<String> domainNames = new ArrayList<>();
        try {
            while (sqlData.next()) {
                String data = sqlData.getString("name_value");
                // add all names to domain list, before that cut first and last character, cause data format is like
                // {xxx} and split names with ","
                domainNames.addAll(
                        Arrays.stream(data.substring(1, data.length() - 1).split(",")).collect(Collectors.toList()));
            }
            // remove all repeatable names and parent domain name (with wildcard too) from results
            // convert data to Domain objects
            // TODO how to handle wildcards? wildcards are also useful info, maybe it should just be removed?
            return domainNames
                    .stream()
                    .distinct()
                    .filter(e -> !e.equals(domain))
                    .filter(e -> !e.startsWith("*." + domain))
                    .filter(e -> e.endsWith("." + domain))
                    .map(e -> new Domain(e, DomainSource.CERT_TRANSPARENCY, domain))
                    .collect(Collectors.toList());
        } catch (SQLException e) {
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return new ArrayList<>();
    }
}
