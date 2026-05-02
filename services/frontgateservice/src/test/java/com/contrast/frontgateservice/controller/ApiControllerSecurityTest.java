package com.contrast.frontgateservice.controller;

import com.contrast.frontgateservice.service.DataServiceProxy;
import com.contrast.frontgateservice.service.ImageServiceProxy;
import com.contrast.frontgateservice.service.WebhookServiceProxy;
import com.contrast.frontgateservice.service.UserService;
import com.contrast.frontgateservice.service.LabelServiceProxy;
import com.contrast.frontgateservice.service.DocServiceProxy;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WebMvcTest(ApiController.class)
@AutoConfigureMockMvc(addFilters = false)
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
    void trackShipment_withXssPayload_shouldEscapeHtmlInResponse() throws Exception {
        String xssPayload = "<script>alert('XSS')</script>";
        String emptyResponse = "{\"_embedded\":{\"shipments\":[]}}";

        when(dataServiceProxy.getShipmentByTrackingId(anyString()))
                .thenReturn(ResponseEntity.ok(emptyResponse));

        MvcResult result = mockMvc.perform(get("/api/shipments/track")
                        .param("trackingId", xssPayload))
                .andExpect(status().isNotFound())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        assertFalse(responseBody.contains("<script>"),
                "Response must not contain unescaped <script> tag");
        assertFalse(responseBody.contains("alert('XSS')"),
                "Response must not contain unescaped JavaScript");
        assertTrue(responseBody.contains("&lt;script&gt;"),
                "Response should contain HTML-escaped script tag");
    }

    @Test
    void trackShipment_withSafeInput_shouldReturnNotFoundMessage() throws Exception {
        String safeTrackingId = "TRACK-12345";
        String emptyResponse = "{\"_embedded\":{\"shipments\":[]}}";

        when(dataServiceProxy.getShipmentByTrackingId(anyString()))
                .thenReturn(ResponseEntity.ok(emptyResponse));

        MvcResult result = mockMvc.perform(get("/api/shipments/track")
                        .param("trackingId", safeTrackingId))
                .andExpect(status().isNotFound())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        assertTrue(responseBody.contains("TRACK-12345"),
                "Response should contain the safe tracking ID");
        assertTrue(responseBody.contains("not found"),
                "Response should contain not found message");
    }
}
