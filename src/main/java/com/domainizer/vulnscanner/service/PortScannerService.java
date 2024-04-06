package com.domainizer.vulnscanner.service;

import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.RunVulnScan;
import com.domainizer.vulnscanner.repository.OpenPortRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class PortScannerService {

    private static final Logger logger = LoggerFactory.getLogger(PortScannerService.class);
    @Autowired
    private OpenPortRepository openPortRepository;

    public void scanPortsForDomainScanResults(List<String> ipAddresses, String portsToScan, RunVulnScan runVulnScan) {
        for (String ipAddress : ipAddresses) {
            scanPorts(ipAddress, portsToScan, runVulnScan);
        }
    }

    private void scanPorts(String address, String portsToScan, RunVulnScan runVulnScan) {
        List<Integer> openPorts = new ArrayList<>();
        for (Integer openPort : parsePortsToScan(portsToScan)) {
            try {
                // service returns String for now - should boolean
                // if service is null (result from portIsOpen() function, then port is closed
                // otherwise open
                String service = portIsOpen(address, openPort);
                if (service != null) {
                    openPorts.add(openPort);
                    openPortRepository.save(new OpenPort(openPort, address, service, runVulnScan));
                }
            } catch (Exception e) {
                logger.error("Error while running port scan against {0}", address);
                logger.error(Arrays.toString(e.getStackTrace()));
            }
        }
    }

    // TODO should not return string but bool - service identification should be done other way
    // but I do not want to make another socket connection for that if I can do it in one connection
    private String portIsOpen(String ip, int port) {
        String service = "";
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(ip, port), 200);
            socket.setKeepAlive(true);

            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // TODO test for other services - like SMTP, FTP etc
            // TODO and enchance detection of HTTP(S) services
            // maybe some http requests if this is common http port?
            out.write("GET / HTTP/1.1");
            out.newLine();
            out.flush();

            socket.shutdownOutput();
            service = determineService(in.readLine());

            socket.shutdownInput();
            out.close();
            in.close();
            socket.close();

            return service;
        } catch (IOException ex) {
            return null;
        }
    }

    private String determineService(String banner) {
        if (banner == null) return "";
        banner = banner.toLowerCase();
        String service = "";
        if (banner.contains("http")) service = "HTTP";
        else if (banner.contains("pop3")) service = "POP3";
        else if (banner.contains("imap")) service = "IMAP";
        else if (banner.contains("ssh")) service = "SSH";
        else if (banner.contains("ftp")) service = "FTP";
        else if (banner.contains("dns")) service = "DNS";
        else if (banner.contains("smb") || banner.contains("samba")) service = "SMB";
        else if (banner.contains("telnet")) service = "Telnet";
        else if (banner.contains("sql")) service = "SQL";
        return service;
    }

    private int[] parsePortsToScan(String ports) {
        return Arrays.stream(ports.split(","))
                .mapToInt(Integer::parseInt)
                .toArray();
    }

    private void checkServiceOnPort(String ipAddress, String port) {

    }
}
