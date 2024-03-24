package com.domainizer.domainscanner.repository;

import com.domainizer.domainscanner.model.RunScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RunScanRepository extends JpaRepository<RunScan, Long> {

    List<RunScan> findByScanId(Long scan_id);
}
