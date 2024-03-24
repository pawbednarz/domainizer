package com.domainizer.domainscanner.model;

public enum DomainSource {
    SEARCH_ENG_GOOGLE("Search Enginge (Google)"),
    CERT_TRANSPARENCY("Certificate Transparency"),
    ZONE_TRANSFER("Zone Transfer"),
    SAN("Subject Alternative Name"),
    DNS_RECORD("DNS records"),
    DICTIONARY("Dictionary"),
    API_VIRUS_TOTAL("Virus Total API"),
    CSP("Content Security Policy");

    private final String source;

    DomainSource(String source) {
        this.source = source;
    }

    public String getSource() {
        return source;
    }
}
