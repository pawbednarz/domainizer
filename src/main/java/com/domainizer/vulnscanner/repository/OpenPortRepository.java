package com.domainizer.vulnscanner.repository;

import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.RunVulnScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface OpenPortRepository extends JpaRepository<OpenPort, Long> {
    List<OpenPort> findAllByRunVulnScanId(Long vulnScanId);

    List<OpenPort> findAllByRunVulnScan(RunVulnScan runVulnScan);

    @Query("SELECT o FROM OpenPort o WHERE o.runVulnScan = :runVulnScan AND o.ipAddress = :ipAddress")
    List<OpenPort> findAllByRunVulnScanIdAndIpAddress(
            @Param("runVulnScan") RunVulnScan runVulnScan,
            @Param("ipAddress") String ipAddress
    );
}
