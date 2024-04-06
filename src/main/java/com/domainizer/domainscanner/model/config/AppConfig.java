package com.domainizer.domainscanner.model.config;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;

@Entity
public class AppConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_app_config")
    @JsonIgnore
    private Long id;

    @Column(name = "virus_total_key")
    private String virusTotalKey;

    @Column(name = "censys_api_id")
    private String censysApiId;

    @Column(name = "censys_api_secret")
    private String censysApiSecret;

    @Column(name = "shodan_api_secret")
    private String shodanApiSecret;

    @Column(name = "api_ninjas_key")
    private String apiNinjasKey;

    public AppConfig() {
    }

    public AppConfig(String virusTotalKey, String censysApiId, String censysApiSecret, String shodanApiSecret, String apiNinjasKey) {
        this.virusTotalKey = virusTotalKey;
        this.censysApiId = censysApiId;
        this.censysApiSecret = censysApiSecret;
        this.shodanApiSecret = shodanApiSecret;
        this.apiNinjasKey = apiNinjasKey;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getVirusTotalKey() {
        return virusTotalKey;
    }

    public void setVirusTotalKey(String virusTotalKey) {
        this.virusTotalKey = virusTotalKey;
    }

    public String getCensysApiId() {
        return censysApiId;
    }

    public void setCensysApiId(String censysApiID) {
        this.censysApiId = censysApiID;
    }

    public String getCensysApiSecret() {
        return censysApiSecret;
    }

    public void setCensysApiSecret(String censysApiSecret) {
        this.censysApiSecret = censysApiSecret;
    }

    public String getShodanApiSecret() {
        return shodanApiSecret;
    }

    public void setShodanApiSecret(String shodanApiSecret) {
        this.shodanApiSecret = shodanApiSecret;
    }

    public String getApiNinjasKey() {
        return apiNinjasKey;
    }

    public void setApiNinjasKey(String apiNinjasKey) {
        this.apiNinjasKey = apiNinjasKey;
    }
}
