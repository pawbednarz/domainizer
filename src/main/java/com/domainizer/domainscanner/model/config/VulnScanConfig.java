package com.domainizer.domainscanner.model.config;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "vuln_scan_config")
public class VulnScanConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_vuln_scan_config")
    private Long id;

    @NotNull
    @Column(name = "scanned_ports")
    private String scannedPorts;

    @NotNull
    @Column(name = "unencrypted_communication")
    private boolean unencryptedCommunication;

    @NotNull
    @Column(name = "weak_ssh_credentials")
    private boolean weakSshCredentials;

    @NotNull
    @Column(name = "security_headers")
    private boolean securityHeaders;

    @NotNull
    @Column(name = "ssl_issues")
    private boolean sslIssues;

    public VulnScanConfig() {
    }

    public VulnScanConfig(String scannedPorts, boolean unencryptedCommunication, boolean weakSshCredentials, boolean securityHeaders, boolean sslIssues) {
        this.scannedPorts = scannedPorts;
        this.unencryptedCommunication = unencryptedCommunication;
        this.weakSshCredentials = weakSshCredentials;
        this.securityHeaders = securityHeaders;
        this.sslIssues = sslIssues;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getScannedPorts() {
        return scannedPorts;
    }

    public void setScannedPorts(String scannedPorts) {
        this.scannedPorts = scannedPorts;
    }

    public boolean isUnencryptedCommunication() {
        return unencryptedCommunication;
    }

    public void setUnencryptedCommunication(boolean unencryptedCommunication) {
        this.unencryptedCommunication = unencryptedCommunication;
    }

    public boolean isWeakSshCredentials() {
        return weakSshCredentials;
    }

    public void setWeakSshCredentials(boolean weakSshCredentials) {
        this.weakSshCredentials = weakSshCredentials;
    }

    public boolean isSecurityHeaders() {
        return securityHeaders;
    }

    public void setSecurityHeaders(boolean securityHeaders) {
        this.securityHeaders = securityHeaders;
    }

    public boolean isSslIssues() {
        return sslIssues;
    }

    public void setSslIssues(boolean sslIssues) {
        this.sslIssues = sslIssues;
    }
}
