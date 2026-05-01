package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.DocServiceProxy;
import com.contrast.frontgateservice.service.ImageServiceProxy;
import com.contrast.frontgateservice.service.LabelServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import com.contrast.frontgateservice.service.WebhookServiceProxy;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.*;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ApiController.class)
class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DataServiceProxy dataServiceProxy;

    @MockBean
    private ImageServiceProxy imageServiceProxy;

    @MockBean
    private WebhookServiceProxy webhookServiceProxy;

    @MockBean
    private LabelServiceProxy labelServiceProxy;

    @MockBean
    private DocServiceProxy docServiceProxy;

    @MockBean
    private UserService userService;

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_rejectsMaliciousPayload() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new MaliciousPayload());
        oos.close();

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "payload.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file).with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Invalid file format"));
    }

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_acceptsValidAddressList() throws Exception {
        User mockUser = new User();
        mockUser.setId(1L);
        mockUser.setUsername("testuser");
        when(userService.findByUsername("testuser")).thenReturn(mockUser);
        when(dataServiceProxy.createAddress(any())).thenReturn(
                ResponseEntity.ok("{\"id\": 1}"));

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

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.ser",
                "application/octet-stream",
                baos.toByteArray()
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.saved").value(1));
    }

    private static class MaliciousPayload implements Serializable {
        private static final long serialVersionUID = 1L;
    }
}
