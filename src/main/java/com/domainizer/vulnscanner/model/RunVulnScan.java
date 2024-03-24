package com.domainizer.vulnscanner.model;

import com.domainizer.domainscanner.model.RunScan;
import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
public class RunVulnScan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_run_vuln_scan")
    private Long id;

    @Column(name = "start_date")
    private LocalDateTime startDateTime;

    @Column(name = "finish_date")
    private LocalDateTime finishDateTime;

    @ManyToOne
    @JoinColumn(name = "run_scan_id")
    @JsonIgnore
    private RunScan runScan;

    @OneToMany(mappedBy = "runVulnScan", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<OpenPort> openPorts;

    public RunVulnScan() {
    }

    public RunVulnScan(RunScan runScan) {
        this.startDateTime = LocalDateTime.now();
        this.runScan = runScan;
    }

    public RunVulnScan(LocalDateTime startDateTime, LocalDateTime finishDateTime, RunScan runScan) {
        this.startDateTime = startDateTime;
        this.finishDateTime = finishDateTime;
        this.runScan = runScan;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public LocalDateTime getStartDateTime() {
        return startDateTime;
    }

    public void setStartDateTime(LocalDateTime startDateTime) {
        this.startDateTime = startDateTime;
    }

    public LocalDateTime getFinishDateTime() {
        return finishDateTime;
    }

    public void setFinishDateTime(LocalDateTime finishDateTime) {
        this.finishDateTime = finishDateTime;
    }

    public RunScan getScan() {
        return runScan;
    }

    public void setScan(RunScan runScan) {
        this.runScan = runScan;
    }

    public List<OpenPort> getOpenPorts() {
        return openPorts;
    }

    public void setOpenPorts(List<OpenPort> openPorts) {
        this.openPorts = openPorts;
    }
}
