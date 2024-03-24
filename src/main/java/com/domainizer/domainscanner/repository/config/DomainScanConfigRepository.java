package com.domainizer.domainscanner.repository.config;

import com.domainizer.domainscanner.model.config.DomainScanConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DomainScanConfigRepository extends JpaRepository<DomainScanConfig, Long> {
}
