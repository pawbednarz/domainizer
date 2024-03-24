package com.domainizer.vulnscanner.service.scanner;

import com.domainizer.vulnscanner.model.SecurityIssue;
import com.domainizer.vulnscanner.model.IpPortScanHelper;

import java.util.List;

public interface IVulnScanner {

    List<SecurityIssue> runScan(List<IpPortScanHelper> ipPortScanHelperList);
}
