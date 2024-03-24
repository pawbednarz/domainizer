package com.domainizer.domainscanner.repository.config;

import com.domainizer.domainscanner.model.config.AppConfig;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppConfigRepository extends JpaRepository<AppConfig, Long> {
}
