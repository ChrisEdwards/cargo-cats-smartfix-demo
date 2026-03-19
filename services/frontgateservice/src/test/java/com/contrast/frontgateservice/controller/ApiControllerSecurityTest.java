package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.DocServiceProxy;
import com.contrast.frontgateservice.service.ImageServiceProxy;
import com.contrast.frontgateservice.service.LabelServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import com.contrast.frontgateservice.service.WebhookServiceProxy;
import com.contrast.frontgateservice.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class ApiControllerSecurityTest {

    private MockMvc mockMvc;

    @Mock
    private DataServiceProxy dataServiceProxy;

    @Mock
    private ImageServiceProxy imageServiceProxy;

    @Mock
    private WebhookServiceProxy webhookServiceProxy;

    @Mock
    private LabelServiceProxy labelServiceProxy;

    @Mock
    private DocServiceProxy docServiceProxy;

    @Mock
    private UserService userService;

    @InjectMocks
    private ApiController apiController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(apiController).build();
    }

    @Test
    void importAddresses_rejectsMaliciousPayload() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(new MaliciousPayload());
        }

        MockMultipartFile file = new MockMultipartFile(
                "file", "payload.ser", "application/octet-stream", baos.toByteArray());

        mockMvc.perform(multipart("/api/addresses/import").file(file))
                .andExpect(status().is5xxServerError())
                .andExpect(content().string(containsString("Import failed")));

        verify(dataServiceProxy, never()).createAddress(any());
    }

    @Test
    void importAddresses_acceptsValidPayload() throws Exception {
        // Set up SecurityContext so the controller can get the authenticated user
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("testuser", "password", Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(auth);

        User user = new User("testuser", "password");
        user.setId(1L);
        when(userService.findByUsername("testuser")).thenReturn(user);
        when(dataServiceProxy.createAddress(any()))
                .thenReturn(ResponseEntity.ok("{\"id\": 1}"));

        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "Springfield");
        address.put("state", "IL");
        address.put("zip", "62701");
        addresses.add(address);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(addresses);
        }

        MockMultipartFile file = new MockMultipartFile(
                "file", "addresses.ser", "application/octet-stream", baos.toByteArray());

        mockMvc.perform(multipart("/api/addresses/import").file(file))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("saved")));
    }

    static class MaliciousPayload implements java.io.Serializable {
        private static final long serialVersionUID = 1L;
    }
}
