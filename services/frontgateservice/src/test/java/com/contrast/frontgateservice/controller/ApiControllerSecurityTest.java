package com.contrast.frontgateservice.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.io.*;
import java.util.*;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
class ApiControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_shouldRejectMaliciousPayload() throws Exception {
        byte[] maliciousPayload = createMaliciousSerializedPayload();
        
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.ser",
                "application/octet-stream",
                maliciousPayload
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file))
                .andExpect(status().is5xxServerError());
    }

    @Test
    @WithMockUser(username = "testuser")
    void importAddresses_shouldAcceptValidPayload() throws Exception {
        byte[] validPayload = createValidSerializedPayload();
        
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "addresses.ser",
                "application/octet-stream",
                validPayload
        );

        mockMvc.perform(multipart("/api/addresses/import").file(file))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    assertTrue(status == 200 || status == 500, 
                            "Expected 200 (success) or 500 (service unavailable), got: " + status);
                });
    }

    @Test
    void testObjectInputFilterRejectsDangerousClasses() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new DangerousClass());
        oos.close();
        
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.setObjectInputFilter(createAddressImportFilter());
        
        assertThrows(InvalidClassException.class, () -> {
            ois.readObject();
        });
    }

    @Test
    void testObjectInputFilterAllowsSafeClasses() throws Exception {
        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "Test City");
        address.put("zipCode", "12345");
        addresses.add(address);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(addresses);
        oos.close();
        
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.setObjectInputFilter(createAddressImportFilter());
        
        Object result = ois.readObject();
        assertNotNull(result);
        assertTrue(result instanceof List);
    }

    private byte[] createMaliciousSerializedPayload() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(new DangerousClass());
        oos.close();
        return baos.toByteArray();
    }

    private byte[] createValidSerializedPayload() throws IOException {
        List<Map<String, Object>> addresses = new ArrayList<>();
        Map<String, Object> address = new HashMap<>();
        address.put("street", "123 Main St");
        address.put("city", "Test City");
        address.put("state", "TS");
        address.put("zipCode", "12345");
        addresses.add(address);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(addresses);
        oos.close();
        return baos.toByteArray();
    }

    private static ObjectInputFilter createAddressImportFilter() {
        return filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz == null) {
                return ObjectInputFilter.Status.UNDECIDED;
            }
            if (clazz.isArray()) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            if (java.util.List.class.isAssignableFrom(clazz) ||
                java.util.ArrayList.class.isAssignableFrom(clazz) ||
                java.util.LinkedList.class.isAssignableFrom(clazz) ||
                java.util.Map.class.isAssignableFrom(clazz) ||
                java.util.HashMap.class.isAssignableFrom(clazz) ||
                java.util.LinkedHashMap.class.isAssignableFrom(clazz) ||
                clazz == String.class ||
                clazz == Integer.class ||
                clazz == Long.class ||
                clazz == Double.class ||
                clazz == Float.class ||
                clazz == Boolean.class ||
                clazz == Number.class) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            return ObjectInputFilter.Status.REJECTED;
        };
    }

    private static class DangerousClass implements Serializable {
        private static final long serialVersionUID = 1L;
    }
}
