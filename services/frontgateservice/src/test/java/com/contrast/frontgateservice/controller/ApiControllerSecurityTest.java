package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.entity.User;
import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.ImageServiceProxy;
import com.contrast.frontgateservice.service.WebhookServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import com.contrast.frontgateservice.service.LabelServiceProxy;
import com.contrast.frontgateservice.service.DocServiceProxy;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
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
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

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
    private UserService userService;

    @MockBean
    private LabelServiceProxy labelServiceProxy;

    @MockBean
    private DocServiceProxy docServiceProxy;

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_rejectsMaliciousPayload() throws Exception {
        byte[] maliciousPayload = createMaliciousSerializedPayload();

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "payload.ser",
                "application/octet-stream",
                maliciousPayload
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file).with(csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(containsString("Import failed")))
                .andExpect(content().string(containsString("REJECTED")));
    }

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_acceptsValidPayload() throws Exception {
        User mockUser = new User();
        mockUser.setId(1L);
        mockUser.setUsername("testuser");
        when(userService.findByUsername("testuser")).thenReturn(mockUser);
        when(dataServiceProxy.createAddress(any())).thenReturn(
                ResponseEntity.ok("{\"id\": 1}"));

        byte[] validPayload = createValidSerializedPayload();

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.ser",
                "application/octet-stream",
                validPayload
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("saved")));
    }

    private byte[] createMaliciousSerializedPayload() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new java.net.URL("http://evil.com"));
        oos.close();
        return baos.toByteArray();
    }

    private byte[] createValidSerializedPayload() throws Exception {
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
        return baos.toByteArray();
    }
}
