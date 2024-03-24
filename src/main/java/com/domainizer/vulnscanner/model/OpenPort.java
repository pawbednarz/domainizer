package com.domainizer.vulnscanner.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.List;

@Entity
public class OpenPort {

    @OneToMany(mappedBy = "openPort", cascade = CascadeType.REMOVE, orphanRemoval = true)
    List<SecurityIssue> securityIssue;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_open_port")
    private Long id;
    @NotNull
    private int openPort;
    @NotNull
    private String ipAddress;
    private String service;
    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "run_vuln_scan_id")
    @JsonIgnore
    private RunVulnScan runVulnScan;

    public OpenPort() {
    }

    public OpenPort(int openPort, String ipAddress, String service, RunVulnScan runVulnScan) {
        this.openPort = openPort;
        this.ipAddress = ipAddress;
        this.service = service;
        this.runVulnScan = runVulnScan;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public int getOpenPort() {
        return openPort;
    }

    public void setOpenPort(int openPort) {
        this.openPort = openPort;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public RunVulnScan getRunVulnScan() {
        return runVulnScan;
    }

    public void setRunVulnScan(RunVulnScan runVulnScan) {
        this.runVulnScan = runVulnScan;
    }

    public List<SecurityIssue> getSecurityIssue() {
        return securityIssue;
    }

    public void setSecurityIssue(List<SecurityIssue> securityIssue) {
        this.securityIssue = securityIssue;
    }
}
