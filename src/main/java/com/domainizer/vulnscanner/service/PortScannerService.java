package com.domainizer.vulnscanner.service;

import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.RunVulnScan;
import com.domainizer.vulnscanner.repository.OpenPortRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
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
        } catch (Exception ex) {
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

    // TODO implement concurrency (code below)
//    private void scanPorts(String address, String portsToScan, RunVulnScan runVulnScan) {
//        final ExecutorService es = Executors.newFixedThreadPool(20);
//        final int timeout = 200;
//        final List<Future<ScanResult>> futures = new ArrayList<>();
//        for (int port: parsePortsToScan(portsToScan)) {
//            futures.add(portIsOpen(es, address, port, timeout));
//        }
//        try {
//            es.awaitTermination(200L, TimeUnit.MILLISECONDS);
//        } catch (InterruptedException e) {
//            logger.error("Error while waiting for timeout during port scan against {0}", address);
//            logger.error(Arrays.toString(e.getStackTrace()));
//        }
//        List<Integer> openPorts = new ArrayList<>();
//        for (final Future<ScanResult> f : futures) {
//            try {
//                if (f.get().isOpen()) {
//                    openPorts.add(f.get().getPort());
//                    openPortRepository.save(new OpenPort(f.get().getPort(), address, runVulnScan));
//                }
//            } catch (InterruptedException | ExecutionException e) {
//                logger.error("Error while running port scan against {0}", address);
//                logger.error(Arrays.toString(e.getStackTrace()));
//            }
//        }
//    }
//
//    private static Future<ScanResult> portIsOpen(final ExecutorService es, final String ip, final int port,
//                                                final int timeout) {
//        return es.submit(() -> {
//            try {
//                Socket socket = new Socket();
//                socket.connect(new InetSocketAddress(ip, port), timeout);
//                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
//                DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
//                // https://docs.oracle.com/javase/tutorial/networking/sockets/readingWriting.html
//                // DEBUG
//                // TODO find a way to determine universally
//                // for smtp, ftr etc it might be enough to grab a banner
//                // for HTTP it might be necessary to send GET / HTTP/1.1 line (or also with host header? or just try normal http request?)
//                System.out.println(in.readLine());
//                dos.writeByte(0);
//                dos.flush();
//                dos.close();
//                in.close();
//                socket.close();
//                System.out.println("test");
//                return new ScanResult(port, true);
//            } catch (Exception ex) {
//                return new ScanResult(port, false);
//            }
//        });
//    }

    private int[] parsePortsToScan(String ports) {
        return Arrays.stream(ports.split(","))
                .mapToInt(Integer::parseInt)
                .toArray();
    }

    private void checkServiceOnPort(String ipAddress, String port) {

    }
}
