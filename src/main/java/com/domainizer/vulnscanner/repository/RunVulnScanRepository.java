package com.domainizer.vulnscanner.repository;

import com.domainizer.vulnscanner.model.RunVulnScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RunVulnScanRepository extends JpaRepository<RunVulnScan, Long> {
    List<RunVulnScan> findByRunScanId(Long runScanId);
}
