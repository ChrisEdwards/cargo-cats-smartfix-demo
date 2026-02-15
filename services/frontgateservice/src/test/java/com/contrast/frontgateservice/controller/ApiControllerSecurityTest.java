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

@SpringBootTest
@AutoConfigureMockMvc
class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_withValidSerializedData_shouldSucceed() throws Exception {
        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Test St");
        address.put("city", "Test City");
        address.put("state", "TS");
        address.put("zip", "12345");
        addresses.add(address);

        byte[] serializedData = serializeObject(addresses);
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.ser",
                "application/octet-stream",
                serializedData
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_withMaliciousPayload_shouldReject() throws Exception {
        byte[] maliciousPayload = createMaliciousPayload();
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "malicious.ser",
                "application/octet-stream",
                maliciousPayload
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file))
                .andExpect(status().is5xxServerError());
    }

    private byte[] serializeObject(Object obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.close();
        return baos.toByteArray();
    }

    private byte[] createMaliciousPayload() throws Exception {
        MaliciousClass malicious = new MaliciousClass();
        return serializeObject(malicious);
    }

    private static class MaliciousClass implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
    }
}
