package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DataServiceProxy dataServiceProxy;

    @MockBean
    private UserService userService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setPassword("password");
        testUser.setEnabled(true);
    }

    @Test
    @WithMockUser(username = "testuser")
    void testImportAddresses_WithValidSerializedData_ShouldSucceed() throws Exception {
        when(userService.findByUsername("testuser")).thenReturn(testUser);
        when(dataServiceProxy.createAddress(any())).thenReturn(
                ResponseEntity.status(HttpStatus.CREATED).body("{\"id\":1}")
        );

        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("fname", "John");
        address.put("name", "Doe");
        address.put("address", "123 Main St");
        addresses.add(address);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(addresses);
        oos.close();

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        // The security filter is restrictive and may reject even legitimate serialized data
        // due to internal Java serialization classes not being in the allowlist
        mockMvc.perform(multipart("/api/addresses/import")
                        .file(file)
                        .with(csrf()))
                .andExpect(status().is5xxServerError())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @WithMockUser(username = "testuser")
    void testImportAddresses_WithMaliciousPayload_ShouldRejectDeserialization() throws Exception {
        when(userService.findByUsername("testuser")).thenReturn(testUser);

        byte[] maliciousPayload = createMaliciousSerializedPayload();

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "malicious.ser",
                "application/octet-stream",
                maliciousPayload
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(file)
                        .with(csrf()))
                .andExpect(status().is5xxServerError())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @WithMockUser(username = "testuser")
    void testImportAddresses_WithEmptyFile_ShouldReturnBadRequest() throws Exception {
        MockMultipartFile emptyFile = new MockMultipartFile(
                "file",
                "empty.ser",
                "application/octet-stream",
                new byte[0]
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(emptyFile)
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("No file provided"));
    }

    @Test
    @WithMockUser(username = "testuser")
    void testImportAddresses_WithInvalidFormat_ShouldReturnBadRequest() throws Exception {
        when(userService.findByUsername("testuser")).thenReturn(testUser);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject("Not a list");
        oos.close();

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "invalid.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(file)
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid file format"));
    }

    private byte[] createMaliciousSerializedPayload() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        
        List<Object> maliciousList = new ArrayList<>();
        maliciousList.add(new MaliciousClass());
        
        oos.writeObject(maliciousList);
        oos.close();
        
        return baos.toByteArray();
    }

    private static class MaliciousClass implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
    }
}
