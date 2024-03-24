package com.domainizer.domainscanner.model;

import com.domainizer.domainscanner.model.config.DomainScanConfig;
import com.domainizer.domainscanner.model.config.VulnScanConfig;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.List;

@Entity
public class Scan {

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, orphanRemoval = true)
    List<RunScan> rs;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_scan")
    private Long id;
    @NotNull
    @Size(min = 3, max = 50)
    private String name;
    private String scannedDomain;
    @Column(name = "is_running")
    private boolean isRunning;
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "domain_scan_config_id", referencedColumnName = "id_domain_scan_config")
    @NotNull
    private DomainScanConfig domainScanConfig;
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "vuln_scan_config_id", referencedColumnName = "id_vuln_scan_config")
    @NotNull
    private VulnScanConfig vulnScanConfig;

    public Scan() {
    }

    public Scan(String name,
                String scannedDomain,
                @NotNull DomainScanConfig domainScanConfig) {
        this.name = name;
        this.scannedDomain = scannedDomain;
        this.domainScanConfig = domainScanConfig;
        this.isRunning = false;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getScannedDomain() {
        return scannedDomain;
    }

    public void setScannedDomain(String scannedDomain) {
        this.scannedDomain = scannedDomain;
    }

    public DomainScanConfig getDomainScanConfig() {
        return domainScanConfig;
    }

    public void setDomainScanConfig(DomainScanConfig domainScanConfig) {
        this.domainScanConfig = domainScanConfig;
    }

    public boolean getIsRunning() {
        return isRunning;
    }

    public void setIsRunning(boolean isRunning) {
        this.isRunning = isRunning;
    }

    public boolean isRunning() {
        return isRunning;
    }

    public void setRunning(boolean running) {
        isRunning = running;
    }

    public VulnScanConfig getVulnScanConfig() {
        return vulnScanConfig;
    }

    public void setVulnScanConfig(VulnScanConfig vulnScanConfig) {
        this.vulnScanConfig = vulnScanConfig;
    }

    @Override
    public String toString() {
        return "Scan{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", scannedDomain='" + scannedDomain + '\'' +
                ", domainScanConfig=" + domainScanConfig +
                '}';
    }
}
