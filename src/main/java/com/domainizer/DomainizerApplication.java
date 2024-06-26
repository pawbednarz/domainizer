package com.domainizer;

import com.domainizer.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
public class DomainizerApplication {

    // TODO add startup logs
    static Logger log = LoggerFactory.getLogger(DomainizerApplication.class);

    public static void main(String[] args) {
        Utils.generateJwtKey();
        SpringApplication.run(DomainizerApplication.class, args);
    }
}
