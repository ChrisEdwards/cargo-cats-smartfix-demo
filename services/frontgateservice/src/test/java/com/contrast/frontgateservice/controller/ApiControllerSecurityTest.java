package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import com.contrast.frontgateservice.config.SecurityConfig;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.*;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ApiController.class)
@Import(SecurityConfig.class)
class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DataServiceProxy dataServiceProxy;

    @MockBean
    private com.contrast.frontgateservice.service.ImageServiceProxy imageServiceProxy;

    @MockBean
    private com.contrast.frontgateservice.service.WebhookServiceProxy webhookServiceProxy;

    @MockBean
    private com.contrast.frontgateservice.service.LabelServiceProxy labelServiceProxy;

    @MockBean
    private com.contrast.frontgateservice.service.DocServiceProxy docServiceProxy;

    @MockBean
    private UserService userService;

    @MockBean
    private com.contrast.frontgateservice.service.CustomUserDetailsService customUserDetailsService;

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_rejectsMaliciousPayload() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new java.net.URL("http://evil.com"));
        oos.close();

        MockMultipartFile maliciousFile = new MockMultipartFile(
                "file",
                "payload.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        when(userService.findByUsername("testuser")).thenReturn(user);

        mockMvc.perform(multipart("/api/addresses/import").file(maliciousFile))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_acceptsValidPayload() throws Exception {
        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "Springfield");
        address.put("state", "IL");
        address.put("zip", "62701");
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

        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        when(userService.findByUsername("testuser")).thenReturn(user);
        when(dataServiceProxy.createAddress(any())).thenReturn(
                ResponseEntity.ok("{\"id\": 1}"));

        mockMvc.perform(multipart("/api/addresses/import").file(validFile))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.saved").value(1));
    }
}
