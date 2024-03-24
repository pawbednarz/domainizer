package com.domainizer.vulnscanner.repository;

import com.domainizer.vulnscanner.model.SecurityIssue;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityIssueRepository extends JpaRepository<SecurityIssue, Long> {
}
