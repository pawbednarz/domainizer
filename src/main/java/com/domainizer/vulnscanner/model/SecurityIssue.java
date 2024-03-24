package com.domainizer.vulnscanner.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
public class SecurityIssue {

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "open_port_id")
    @JsonIgnore
    OpenPort openPort;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_security_issue")
    private Long id;
    @NotNull
    private String name;
    @NotNull
    private String description;
    @NotNull
    private String asset;
    // TODO create enum for severity
    @NotNull
    private String severity;

    public SecurityIssue() {
    }

    public SecurityIssue(String name, String description, String asset, String severity, OpenPort openPort) {
        this.name = name;
        this.description = description;
        this.asset = asset;
        this.severity = severity;
        this.openPort = openPort;
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getAsset() {
        return asset;
    }

    public void setAsset(String asset) {
        this.asset = asset;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public OpenPort getOpenPort() {
        return openPort;
    }

    public void setOpenPort(OpenPort openPort) {
        this.openPort = openPort;
    }
}
