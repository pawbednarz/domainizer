package com.domainizer.domainscanner.controller;

import com.domainizer.domainscanner.model.Scan;
import com.domainizer.domainscanner.model.config.DictionaryConfig;
import com.domainizer.domainscanner.model.config.DomainScanConfig;
import com.domainizer.domainscanner.model.config.VulnScanConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ScanControllerTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    private ScanController scanController;

    @Test
    void contextLoads() {
        assertNotNull(scanController);
    }

    @Test
    void shouldReturn403() throws Exception {
        this.mockMvc.perform(get("/shouldNotFound")).andDo(print()).andExpect(status().isForbidden());
    }

    @WithMockUser
    @Test
    void shouldReturn404() throws Exception {
        this.mockMvc.perform(get("/shouldNotFound")).andDo(print()).andExpect(status().isNotFound());
    }

    @WithMockUser
    @Test
    void addScan() throws Exception {
        DomainScanConfig dsc = new DomainScanConfig(
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                new DictionaryConfig()
        );
        dsc.getDictionaryConfig().setDictionaryFile(null);

        VulnScanConfig vsc = new VulnScanConfig(
                "80",
                false,
                false,
                false,
                false
        );

        Scan newScan = new Scan("Test scan", "idonotexist.com1", dsc);
        newScan.setVulnScanConfig(vsc);

        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String newScanJson = ow.writeValueAsString(newScan);

        this.mockMvc.perform(
                        post("/scan/addScan")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(newScanJson)
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    @Test
    void getScans() {
    }

    @Test
    void getScan() {
    }


    @Test
    void runScan() {
    }

    @Test
    void deleteScan() {
    }
}