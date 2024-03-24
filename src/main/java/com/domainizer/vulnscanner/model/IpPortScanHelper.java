package com.domainizer.vulnscanner.model;

import java.util.List;

public class IpPortScanHelper {
    private String ipAddress;
    private List<OpenPort> openPort;
    private List<String> domainNames;

    public IpPortScanHelper(String ipAddress, List<OpenPort> openPort, List<String> domainNames) {
        this.ipAddress = ipAddress;
        this.openPort = openPort;
        this.domainNames = domainNames;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public List<String> getDomainNames() {
        return domainNames;
    }

    public void setDomainNames(List<String> domainNames) {
        this.domainNames = domainNames;
    }

    public List<OpenPort> getOpenPort() {
        return openPort;
    }

    public void setOpenPort(List<OpenPort> openPort) {
        this.openPort = openPort;
    }
}
