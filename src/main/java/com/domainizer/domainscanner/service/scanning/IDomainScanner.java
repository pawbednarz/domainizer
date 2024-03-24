package com.domainizer.domainscanner.service.scanning;

import com.domainizer.domainscanner.model.Domain;
import com.domainizer.domainscanner.model.Scan;

import java.util.List;

public interface IDomainScanner {

    List<Domain> runScan(Scan s);
}
