package com.domainizer.vulnscanner.service.scanner;

import com.domainizer.vulnscanner.model.OpenPort;
import com.domainizer.vulnscanner.model.IpPortScanHelper;
import com.domainizer.vulnscanner.model.SecurityIssue;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class WeakSSHCredentialsService implements IVulnScanner {

    private static final Logger logger = LoggerFactory.getLogger(WeakSSHCredentialsService.class);

    String[] usernames = {
            "Debian-exim",
            "adm",
            "admin",
            "administrator",
            "apache",
            "at",
            "backup",
            "bb",
            "bin",
            "cron",
            "daemon",
            "db2fenc1",
            "db2inst1",
            "ftp",
            "nproc",
            "gdm",
            "gnats",
            "guest",
            "halt",
            "irc",
            "list",
            "lp",
            "ubuntu",
            "mysql",
            "named",
            "ftpuser",
            "ntp",
            "operator",
            "oracle",
            "oracle8",
            "portage",
            "postfix",
            "postgres",
            "postmaster",
            "proxy",
            "public",
            "root",
            "rpc",
            "rwhod",
            "shutdown",
            "smmsp",
            "smmta",
            "squid",
            "sshd",
            "sync",
            "sys",
            "system",
            "test",
            "toor",
            "user",
            "uucp",
            "websphere",
            "www-data"
    };

    String[] passwords = {
            "root",
            "toor",
            "raspberry",
            "dietpi",
            "test",
            "uploader",
            "password",
            "admin",
            "administrator",
            "marketing",
            "12345678",
            "1234",
            "12345",
            "qwerty",
            "webadmin",
            "webmaster",
            "maintenance",
            "techsupport",
            "letmein",
            "logon",
            "Passw@rd",
            "alpine"
    };

    @Override
    public List<SecurityIssue> runScan(List<IpPortScanHelper> ipPortScanHelperList) {
        List<String> ips = ipPortScanHelperList.stream().map(IpPortScanHelper::getIpAddress).collect(Collectors.toList());
        logger.info("Running scan for weak SSH credetnials for " + ips);
        return scanWeahCredentialsOnSSHServices(ipPortScanHelperList);
    }

    // put host and ports
    public List<SecurityIssue> scanWeahCredentialsOnSSHServices(List<IpPortScanHelper> ipPortScanHelperList) {
        List<SecurityIssue> securityIssues = new ArrayList<>();
        ipPortScanHelperList.forEach(hostData -> {
            List<OpenPort> openPort = hostData
                    .getOpenPort()
                    .stream()
                    .filter(el -> el.getService().equals("SSH"))
                    .collect(Collectors.toList());

            for (OpenPort port : openPort) {
                for (String username : usernames) {
                    for (String password : passwords) {
                        SecurityIssue si = authenticateSSH(username, password, hostData.getIpAddress(), port);
                        if (si != null) securityIssues.add(si);
                    }
                }
            }
        });
        return securityIssues;
    }

    private SecurityIssue authenticateSSH(String username, String password, String host, OpenPort port) {

        Session session = null;
        ChannelExec channel = null;
        int openPort = port.getOpenPort();

        try {
            session = new JSch().getSession(username, host, openPort);
            session.setPassword(password);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();

            channel = (ChannelExec) session.openChannel("exec");
            ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
            channel.setOutputStream(responseStream);
            channel.connect();

            while (channel.isConnected()) {
                Thread.sleep(100);
            }

            return new SecurityIssue(
                    "Weak SSH credentials",
                    "It is possible to authenticate to SSH service using weak, easliy guessable credentials. " +
                            "The credentials are " + username + ":" + password,
                    host + ":" + port.getOpenPort(),
                    "Critical",
                    port);
        } catch (Exception e) {
            logger.info("SSH authentication failed on " + host + ":" + port + "for " + username + ":" + password);
            logger.error(Arrays.toString(e.getStackTrace()));
            e.printStackTrace();
        } finally {
            if (session != null) {
                session.disconnect();
            }
            if (channel != null) {
                channel.disconnect();
            }
            return null;
        }
    }
}
