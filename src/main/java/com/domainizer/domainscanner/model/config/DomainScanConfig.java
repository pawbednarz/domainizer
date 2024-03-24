package com.domainizer.domainscanner.model.config;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;

@Entity
public class DomainScanConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_domain_scan_config")
    private Long id;

    @NotNull
    @Column(name = "zone_transfer")
    private boolean zoneTransfer;

    @NotNull
    @Column(name = "certificate_transparency")
    private boolean certificateTransparency;

    @NotNull
    private boolean subjectAlternateName;

    @NotNull
    @Column(name = "dns_aggregators")
    private boolean dnsAggregators;

    @NotNull
    private boolean dnsRecords;

    @NotNull
    private boolean httpHeaders;

    @NotNull
    @Column(name = "search_engines")
    private boolean searchEngines;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "dictionary_config", referencedColumnName = "id_dictionary_config")
    private DictionaryConfig dictionaryConfig;

    @NotNull
    @Column(name = "modified_date")
    private LocalDateTime modifiedDate;

    @Column(name = "modified_by")
    private String modifiedBy;

    public DomainScanConfig() {
        this.modifiedDate = LocalDateTime.now();
    }

    public DomainScanConfig(@NotNull boolean zoneTransfer,
                            @NotNull boolean certificateTransparency,
                            @NotNull boolean subjectAlternateName,
                            @NotNull boolean dnsAggregators,
                            @NotNull boolean dnsRecords,
                            @NotNull boolean httpHeaders,
                            @NotNull boolean searchEngines,
                            DictionaryConfig dictionaryConfig) {
        this.zoneTransfer = zoneTransfer;
        this.certificateTransparency = certificateTransparency;
        this.subjectAlternateName = subjectAlternateName;
        this.dnsAggregators = dnsAggregators;
        this.dnsRecords = dnsRecords;
        this.httpHeaders = httpHeaders;
        this.dictionaryConfig = dictionaryConfig;
        this.searchEngines = searchEngines;
        this.modifiedDate = LocalDateTime.now();
        this.modifiedBy = "Test User";
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public boolean isSearchEngines() {
        return searchEngines;
    }

    public void setSearchEngines(boolean searchEngines) {
        this.searchEngines = searchEngines;
    }

    public boolean isZoneTransfer() {
        return zoneTransfer;
    }

    public void setZoneTransfer(boolean zoneTransfer) {
        this.zoneTransfer = zoneTransfer;
    }

    public boolean isCertificateTransparency() {
        return certificateTransparency;
    }

    public void setCertificateTransparency(boolean certificateTransparency) {
        this.certificateTransparency = certificateTransparency;
    }

    public boolean isSubjectAlternateName() {
        return subjectAlternateName;
    }

    public void setSubjectAlternateName(boolean subjectAlternateName) {
        this.subjectAlternateName = subjectAlternateName;
    }

    public boolean isDnsAggregators() {
        return dnsAggregators;
    }

    public void setDnsAggregators(boolean publicDatasets) {
        this.dnsAggregators = publicDatasets;
    }

    public boolean isDnsRecords() {
        return dnsRecords;
    }

    public void setDnsRecords(boolean dnsRecords) {
        this.dnsRecords = dnsRecords;
    }

    public boolean isHttpHeaders() {
        return httpHeaders;
    }

    public void setHttpHeaders(boolean httpHeaders) {
        this.httpHeaders = httpHeaders;
    }

    public DictionaryConfig getDictionaryConfig() {
        return dictionaryConfig;
    }

    public void setDictionaryConfig(DictionaryConfig dictionaryConfig) {
        this.dictionaryConfig = dictionaryConfig;
    }

    public LocalDateTime getModifiedDate() {
        return modifiedDate;
    }

    public void setModifiedDate(LocalDateTime modifiedDate) {
        this.modifiedDate = modifiedDate;
    }

    public String getModifiedBy() {
        return modifiedBy;
    }

    public void setModifiedBy(String modifiedBy) {
        this.modifiedBy = modifiedBy;
    }
}
