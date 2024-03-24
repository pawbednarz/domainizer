package com.domainizer.domainscanner.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Objects;

@Entity
public class Domain {

    static Logger log = LoggerFactory.getLogger(Domain.class);

    @Id
    @SequenceGenerator(name = "domain_id_domain_seq",
            sequenceName = "domain_id_domain_seq",
            allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE,
            generator = "domain_id_domain_seq")
    @Column(name = "id_domain")
    private Long id;

    @NotNull
    @Size(min = 1, max = 200)
    private String name;

    // TODO validation?
    private DomainSource source;

    private String parentDomain;

    private String ipAddress;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "run_scan_id")
    @JsonIgnore
    private RunScan runScan;

    public Domain() {
    }

    public Domain(@NotNull @Size(min = 1, max = 50) String name) {
        this.name = name;
    }

    public Domain(@NotNull @Size(min = 1, max = 50) String name, @Size(min = 3, max = 30) DomainSource source, String parentDomain) {
        this.name = name;
        this.source = source;
        this.parentDomain = parentDomain;
        try {
            this.ipAddress = InetAddress.getByName(name).getHostAddress();
        } catch (UnknownHostException e) {
            log.error("Error while trying to get IP address for domain " + name);
            log.error(Arrays.toString(e.getStackTrace()));
        }
    }

    public Domain(@NotNull @Size(min = 1, max = 50) String name, @Size(min = 3, max = 30) DomainSource source, String parentDomain, RunScan runScan) {
        this(name, source, parentDomain);
        this.runScan = runScan;
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

    public DomainSource getSource() {
        return source;
    }

    public void setSource(DomainSource source) {
        this.source = source;
    }

    public String getParentDomain() {
        return parentDomain;
    }

    public void setParentDomain(String parentDomain) {
        this.parentDomain = parentDomain;
    }

    public RunScan getRunScan() {
        return runScan;
    }

    public void setRunScan(RunScan runScan) {
        this.runScan = runScan;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    @Override
    public String toString() {
        return "Domain{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", source='" + source + '\'' +
                ", parentDomain='" + parentDomain + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Domain domain = (Domain) o;
        return Objects.equals(name, domain.name) && Objects.equals(parentDomain, domain.parentDomain);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, parentDomain);
    }
}
