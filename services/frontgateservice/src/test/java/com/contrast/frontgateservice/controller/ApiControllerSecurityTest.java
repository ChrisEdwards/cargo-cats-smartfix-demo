package com.contrast.frontgateservice.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

@SpringBootTest
@AutoConfigureMockMvc
class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_shouldRejectMaliciousPayload() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new MaliciousPayload());
        oos.close();

        MockMultipartFile maliciousFile = new MockMultipartFile(
                "file",
                "malicious.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(maliciousFile))
                .andExpect(status().is5xxServerError())
                .andExpect(content().string(containsString("Import failed")));
    }

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_shouldAcceptValidPayload() throws Exception {
        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "Test City");
        address.put("state", "TS");
        address.put("zip", "12345");
        addresses.add(address);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(addresses);
        oos.close();

        MockMultipartFile validFile = new MockMultipartFile(
                "file",
                "addresses.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                .file(validFile))
                .andExpect(status().isOk());
    }

    private static class MaliciousPayload implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
    }
}
