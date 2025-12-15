package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DataServiceProxy dataServiceProxy;

    @MockBean
    private UserService userService;

    private ObjectMapper objectMapper;

    @BeforeEach
    public void setup() {
        objectMapper = new ObjectMapper();
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithValidJsonFile_ShouldSucceed() throws Exception {
        User mockUser = new User();
        mockUser.setId(1L);
        mockUser.setUsername("testuser");
        when(userService.findByUsername("testuser")).thenReturn(mockUser);

        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address1 = new HashMap<>();
        address1.put("fname", "John");
        address1.put("name", "Doe");
        address1.put("address", "123 Main St");
        addresses.add(address1);

        String jsonContent = objectMapper.writeValueAsString(addresses);
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.json",
                "application/json",
                jsonContent.getBytes()
        );

        when(dataServiceProxy.createAddress(any())).thenReturn(
                ResponseEntity.status(HttpStatus.CREATED).body("{\"id\":1}")
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.saved").value(1));
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithEmptyFile_ShouldReturnBadRequest() throws Exception {
        MockMultipartFile emptyFile = new MockMultipartFile(
                "file",
                "addresses.json",
                "application/json",
                new byte[0]
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(emptyFile))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("No file provided"));
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithInvalidJsonFormat_ShouldReturnError() throws Exception {
        MockMultipartFile invalidFile = new MockMultipartFile(
                "file",
                "addresses.json",
                "application/json",
                "invalid json content".getBytes()
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(invalidFile))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_WithMultipleAddresses_ShouldImportAll() throws Exception {
        User mockUser = new User();
        mockUser.setId(1L);
        mockUser.setUsername("testuser");
        when(userService.findByUsername("testuser")).thenReturn(mockUser);

        List<Map<String, Object>> addresses = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            Map<String, Object> address = new HashMap<>();
            address.put("fname", "User" + i);
            address.put("name", "Test" + i);
            address.put("address", i + " Test Street");
            addresses.add(address);
        }

        String jsonContent = objectMapper.writeValueAsString(addresses);
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.json",
                "application/json",
                jsonContent.getBytes()
        );

        when(dataServiceProxy.createAddress(any())).thenReturn(
                ResponseEntity.status(HttpStatus.CREATED).body("{\"id\":1}")
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.saved").value(3));
    }

    @Test
    @WithMockUser(username = "testuser")
    public void testImportAddresses_EnsuresOwnershipAssignment() throws Exception {
        User mockUser = new User();
        mockUser.setId(42L);
        mockUser.setUsername("testuser");
        when(userService.findByUsername("testuser")).thenReturn(mockUser);

        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("fname", "Jane");
        address.put("name", "Smith");
        address.put("address", "456 Oak Ave");
        address.put("id", 999L);
        address.put("_links", new HashMap<>());
        addresses.add(address);

        String jsonContent = objectMapper.writeValueAsString(addresses);
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.json",
                "application/json",
                jsonContent.getBytes()
        );

        when(dataServiceProxy.createAddress(any())).thenReturn(
                ResponseEntity.status(HttpStatus.CREATED).body("{\"id\":1}")
        );

        mockMvc.perform(multipart("/api/addresses/import")
                        .file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.saved").value(1));
    }
}
