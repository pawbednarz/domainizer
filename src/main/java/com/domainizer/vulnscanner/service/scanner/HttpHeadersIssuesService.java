package com.domainizer.vulnscanner.service.scanner;

import com.domainizer.vulnscanner.model.IpPortScanHelper;
import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.SecurityIssue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
public class HttpHeadersIssuesService implements IVulnScanner {

    private static final Logger logger = LoggerFactory.getLogger(HttpHeadersIssuesService.class);

    private final String[] headersToInclude = {
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options"
    };

    // list got from https://owasp.org/www-project-secure-headers/ci/headers_remove.json
    private final String[] headersToRemove = {
            "host-header",
            "k-proxy-request",
            "liferay-portal",
            "oraclecommercecloud-version",
            "pega-host",
            "powered-by",
            "product",
            "server",
            "sourcemap",
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "x-atmosphere-error",
            "x-atmosphere-first-request",
            "x-atmosphere-tracking-id",
            "x-b3-parentspanid",
            "x-b3-sampled",
            "x-b3-spanid",
            "x-b3-traceid",
            "x-beserver",
            "x-cf-powered-by",
            "x-cms",
            "x-calculatedbetarget",
            "x-content-encoded-by",
            "x-diaginfo",
            "x-envoy-attempt-count",
            "x-envoy-external-address",
            "x-envoy-internal",
            "x-envoy-original-dst-host",
            "x-envoy-upstream-service-time",
            "x-feserver",
            "x-framework",
            "x-generated-by",
            "x-generator",
            "x-litespeed-cache",
            "x-litespeed-purge",
            "x-litespeed-tag",
            "x-litespeed-vary",
            "x-litespeed-cache-control",
            "x-mod-pagespeed",
            "x-nextjs-cache",
            "x-nextjs-matched-path",
            "x-nextjs-page",
            "x-nextjs-redirect",
            "x-owa-version",
            "x-old-content-length",
            "x-oneagent-js-injection",
            "x-page-speed",
            "x-php-version",
            "x-powered-by",
            "x-powered-by-plesk",
            "x-powered-cms",
            "x-redirect-by",
            "x-server-powered-by",
            "x-sourcefiles",
            "x-sourcemap",
            "x-turbo-charged-by",
            "x-umbraco-version",
            "x-varnish-backend",
            "x-varnish-server",
            "x-dtagentid",
            "x-dthealthcheck",
            "x-dtinjectedservlet",
            "x-ruxit-js-agent"
    };

    @Override
    public List<SecurityIssue> runScan(List<IpPortScanHelper> ipPortScanHelperList) {
        List<String> ips = ipPortScanHelperList.stream().map(IpPortScanHelper::getIpAddress).collect(Collectors.toList());
        logger.info("Starting scan for security headers on " + ips);
        return checkSecurityHeaders(ipPortScanHelperList);
    }

    private List<SecurityIssue> checkSecurityHeaders(List<IpPortScanHelper> portScanHelperList) {
        List<SecurityIssue> securityIssues = new ArrayList<>();

        portScanHelperList.forEach(hostData -> {

            List<OpenPort> finalOpenPort = hostData
                    .getOpenPort()
                    .stream()
                    .filter(el -> el.getService().equals("HTTP") ||
                            el.getService().equals("HTTPS") ||
                            el.getOpenPort() == 80 ||
                            el.getOpenPort() == 8080 ||
                            el.getOpenPort() == 443)
                    .collect(Collectors.toList());

            hostData.getDomainNames().forEach(domainName -> finalOpenPort.forEach(port -> {
                String protocol = "http";
                if (port.getOpenPort() == 443) protocol = "https";
                List<String> responseHeaderNames = getHttpHeaders(protocol, domainName, port.getOpenPort());
                List<String> toRemove = getHeadersToRemove(responseHeaderNames);
                List<String> toInclude = getMissingHeaders(responseHeaderNames);
                if (!toRemove.isEmpty()) {
                    logger.info("Found new issue: Information disclosure in HTTP response headers for " + domainName + ":" + port);
                    securityIssues.add(new SecurityIssue(
                            "Information disclosure in HTTP response headers",
                            "Server returns HTTP headers in response, which may disclose sensitive " +
                                    "information about the server or application. For example, it can be type of " +
                                    "framework, or exact version of web server used. Identified headers which may " +
                                    "potentially leak information are: " + toRemove,
                            domainName + ":" + port.getOpenPort(),
                            "Low",
                            port
                    ));
                }

                if (!toInclude.isEmpty()) {
                    logger.info("Found new issue: Missing security headers for " + domainName + ":" + port);
                    securityIssues.add(new SecurityIssue(
                            "Missing security headers",
                            "Server does not contain essential HTTP security headers in server response. " +
                                    "Headers which are recommended to be configured in the server response are " + toInclude,
                            domainName + ":" + port.getOpenPort(),
                            "Low",
                            port
                    ));
                }
            }));
        });
        return securityIssues;
    }

    private List<String> getHttpHeaders(String protocol, String address, int port) {
        URL url;
        try {
            url = new URL(protocol + "://" + address + ":" + port);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        if (protocol.equals("http")) {
            return getHttpHeaders(url);
        } else {
            return getHttpsHeaders(url);
        }
    }

    private List<String> getHeadersToRemove(List<String> responseHeaderNames) {
        List<String> removeHeaders = new ArrayList<>();
        List<String> resHeaders = responseHeaderNames
                .stream()
                .filter(Objects::nonNull)
                .map(String::toLowerCase)
                .collect(Collectors.toList());
        for (String header : headersToRemove) {
            if (resHeaders.contains(header)) {
                removeHeaders.add(header);
            }
        }
        return removeHeaders;
    }

    private List<String> getMissingHeaders(List<String> responseHeaderNames) {
        List<String> missingHeaders = new ArrayList<>();
        List<String> resHeaders = responseHeaderNames
                .stream()
                .filter(Objects::nonNull)
                .map(String::toLowerCase)
                .collect(Collectors.toList());
        for (String header : headersToInclude) {
            if (!resHeaders.contains(header)) {
                missingHeaders.add(header);
            }
        }
        return missingHeaders;
    }

    private List<String> getHttpHeaders(URL url) {
        HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) url.openConnection();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            System.out.println(conn.getResponseCode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        List<String> headerNames = new ArrayList<>();
        conn.getHeaderFields().forEach((k, v) -> headerNames.add(k));
        return headerNames;
    }

    private List<String> getHttpsHeaders(URL url) {
        HttpsURLConnection conn;
        try {
            conn = (HttpsURLConnection) url.openConnection();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        conn.setHostnameVerifier((s, sslSession) -> true);

        try {
            System.out.println(conn.getResponseCode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        List<String> headerNames = new ArrayList<>();
        conn.getHeaderFields().forEach((k, v) -> headerNames.add(k));
        return headerNames;
    }
}