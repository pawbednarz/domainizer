package com.domainizer.domainscanner.repository;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.RunScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DomainRepository extends JpaRepository<Domain, Long> {

    List<Domain> findAllByRunScanId(Long runScanId);

    int countByRunScan(RunScan runScan);

    @Query("SELECT DISTINCT d.ipAddress FROM Domain d WHERE d.runScan = :runScan")
    List<String> findAllIpAddressByRunScanId(@Param("runScan") RunScan runScan);

    @Query("SELECT d.name FROM Domain d WHERE d.runScan = :runScan AND d.ipAddress = :ipAddress")
    List<String> findAllDomainsByRunScanIdAndIpAddress(
            @Param("runScan") RunScan runScan,
            @Param("ipAddress") String ipAddress
    );

    @Query("SELECT COUNT(DISTINCT d.ipAddress) FROM Domain d WHERE d.runScan = :runScan")
    int getIpAddress(@Param("runScan") RunScan runScan);
}
