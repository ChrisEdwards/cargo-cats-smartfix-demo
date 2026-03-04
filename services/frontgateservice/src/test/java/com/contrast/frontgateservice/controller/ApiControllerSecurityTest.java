package com.contrast.frontgateservice.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.*;

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
    void importAddresses_rejectsMaliciousPayload() throws Exception {
        byte[] maliciousPayload = createMaliciousSerializedPayload();
        
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "malicious.ser",
                "application/octet-stream",
                maliciousPayload
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file))
                .andExpect(status().is5xxServerError())
                .andExpect(content().string(containsString("Import failed")));
    }

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_rejectsUnauthorizedClass() throws Exception {
        byte[] unauthorizedClassPayload = createUnauthorizedClassPayload();
        
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "unauthorized.ser",
                "application/octet-stream",
                unauthorizedClassPayload
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file))
                .andExpect(status().is5xxServerError())
                .andExpect(content().string(containsString("Import failed")));
    }

    private byte[] createMaliciousSerializedPayload() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new MaliciousObject());
        oos.close();
        return baos.toByteArray();
    }

    private byte[] createUnauthorizedClassPayload() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new UnauthorizedClass("test"));
        oos.close();
        return baos.toByteArray();
    }

    private static class MaliciousObject implements Serializable {
        private static final long serialVersionUID = 1L;
        
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            throw new RuntimeException("Malicious code would execute here");
        }
    }

    private static class UnauthorizedClass implements Serializable {
        private static final long serialVersionUID = 1L;
        private String data;
        
        public UnauthorizedClass(String data) {
            this.data = data;
        }
    }
}
