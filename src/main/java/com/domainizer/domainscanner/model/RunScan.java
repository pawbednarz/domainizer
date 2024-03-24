package com.domainizer.domainscanner.model;

import com.domainizer.vulnscanner.model.RunVulnScan;
import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
public class RunScan {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_run_scan")
    private Long id;

    @Column(name = "start_date")
    private LocalDateTime startDateTime;

    @Column(name = "finish_date")
    private LocalDateTime finishDateTime;

    @ManyToOne
    @JoinColumn(name = "scan_id")
    @JsonIgnore
    private Scan scan;

    @OneToMany(mappedBy = "runScan", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Domain> ds;

    @OneToMany(mappedBy = "runScan", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @JsonIgnore
    private List<RunVulnScan> runVulnScan;

    public RunScan() {

    }

    public RunScan(Scan scan) {
        this.startDateTime = LocalDateTime.now();
        this.scan = scan;
    }

    public RunScan(LocalDateTime startDateTime, LocalDateTime finishDateTime, Scan scan) {
        this.startDateTime = startDateTime;
        this.finishDateTime = finishDateTime;
        this.scan = scan;
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

    public Scan getScan() {
        return scan;
    }

    public void setScan(Scan scan) {
        this.scan = scan;
    }
}
